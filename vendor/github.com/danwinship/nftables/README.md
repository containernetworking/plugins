# golang nftables library

This is a library for using nftables from Go.

It is not intended to support arbitrary use cases, but instead
specifically focuses on supporing Kubernetes components which are
using nftables in the way that nftables is supposed to be used (as
opposed to using nftables in a naively-translated-from-iptables way,
or using nftables to do totally valid things that aren't the sorts of
things Kubernetes components are likely to need to do).

It is still under development and is not API stable.

## Usage

Create an `Interface` object to manage operations on a single nftables
table:

```golang
nft := nftables.New(nftables.IPv4Family, "my-table")

// Make sure nftables actually works here
if err := nft.Present(); err != nil {
        return fmt.Errorf("no nftables support: %v", err)
}
```

The `Define` method can be used to add defines (as with `nft -D
name=value`) to an `Interface` which can then be referenced with
`$name` in transactions. If you are using `IPv4Family` or `IPv6Family`
then you automatically get the defines `IP` (`"ip"` or `"ip6"`) and
`INET_ADDR` (`"ipv4_addr"` or `"ipv6_addr"`) which can be used to
allow the same rules and set/map definitions to be used for IPv4 and
IPv6.

You can use the `List`, `ListRules`, and `ListElements` methods on the
`Interface` to check if objects exist. `List` returns the names of
`"chains"`, `"sets"`, or `"maps"` in the table, while `ListRules` and
`ListElements` return `Rule` and `Element` objects.

```golang
chains, err := nft.List(ctx, "chains")
if err != nil {
        return fmt.Errorf("could not list chains: %v", err)
}

FIXME

elements, err := nft.ListElements(ctx, "map", "mymap")
if err != nil {
        return fmt.Errorf("could not list map elements: %v", err)
}

FIXME
```

To make changes, create a `Transaction`, add the appropriate
operations to the transaction, and then call `nft.Run` on it:

```golang
tx := nftables.NewTransaction()

tx.Add(&nftables.Chain{
        Name:    "mychain",
        Comment: nftables.Optional("this is my chain"),
})
tx.Flush(&nftables.Chain{
        Name: "mychain",
})

var destIP net.IP
var destPort uint16
...
tx.Add(&nftables.Rule{
        Chain: "mychain",
        Rule:  nftables.Concat(
                "$IP daddr", destIP,
                "$IP protocol", "tcp",
                "th port", destPort,
                "jump", destChain,
        )
})

err := nft.Run(context, tx)
```

If any operation in the transaction would fail, then `Run()` will
return an error and the entire transaction will be ignored. You can
use the `nftables.IsNotFound()` and `nft.IsAlreadyExists()` methods to
check for those well-known error types. In a large transaction, there
is no supported way to determine exactly which operation failed.

## `nftables.Transaction` operations

`nftables.Transaction` operations correspond to the top-level commands
in the `nft` binary. Currently-supported operations are:

- `tx.Add()`: adds an object, which may already exist, as with `nft add`
- `tx.Create()`: creates an object, which must not already exist, as with `nft create`
- `tx.Flush()`: flushes the contents of a table/chain/set/map, as with `nft flush`
- `tx.Delete()`: deletes an object, as with `nft delete`
- `tx.Insert()`: inserts a rule before another rule, as with `nft insert rule`
- `tx.Replace()`: replaces a rule, as with `nft replace rule`

## Objects

The `Transaction` methods take arguments of type `nftables.Object`.
The currently-supported objects are:

- `Table`
- `Chain`
- `Rule`
- `Set`
- `Map`
- `Element`

Optional fields in objects can be filled in with the help of the
`Optional()` function, which just returns a pointer to its
argument.

`Concat()` can be used to concatenate a series of strings, `[]string`
arrays, and other arguments (including numbers, `net.IP`s /
`net.IPNet`s, and anything else that can be formatted usefully via
`fmt.Sprintf("%s")`) together into a single string. This is often
useful when constructing `Rule`s.

The `Join()` and `Split()` helper functions can be used with set and
map keys and values, to convert between multiple values specified
separately, and a single string with the values separated by dots.

## `nftables.Fake`

There is a fake (in-memory) implementation of `nftables.Interface` for
use in unit tests. Use `nftables.NewFake()` instead of
`nftables.New()` to create it, and then it should work mostly the
same. See `fake.go` for more details of the public APIs for examining
the current state of the fake nftables database.

Note that at the present time, `fake.Run()` is not actually
transactional, so unit tests that rely on things not being changed if
a transaction fails partway through will not work as expected.

## Missing APIs

Various top-level object types are not yet supported (notably the
"stateful objects" like `counter`).

Most IPTables libraries have an API for "add this rule only if it
doesn't already exist", but that does not seem as useful in nftables
(or at least "in nftables as used by Kubernetes-ish components that
aren't just blindly copying over old iptables APIs"), because chains
tend to have static rules and dynamic sets/maps, rather than having
dynamic rules. If you aren't sure if a chain has the correct rules,
you can just `Flush` it and recreate all of the rules.

I've considered changing the semantics of `tx.Add(obj)` so that
`obj.Handle` is filled in with the new object's handle on return from
`Run()`, for ease of deleting later. (This would be implemented by
using the `--handle` (`-a`) and `--echo` (`-e`) flags to `nft add`.)
However, this would require potentially difficult parsing of the `nft`
output. `ListRules` fills in the handles of the rules it returns, so
it's possible to find out a rule's handle after the fact that way. For
other supported object types, either handles don't exist (`Element`)
or you don't really need to know their handles because it's possible
to delete by name instead (`Table`, `Chain`, `Set`, `Map`).

The "destroy" (delete-without-ENOENT) command that exists in newer
versions of `nft` is not currently supported because it would be
unexpectedly heavyweight to emulate on systems that don't have it, so
it is better (for now) to force callers to implement it by hand.

# Design Notes

The library works by invoking the `nft` binary, mostly not using the
`--json` mode.

Although it might seem like we ought to use either the low-level
(netlink) interface, or at least the JSON interface, that doesn't seem
like a good idea in practice. The documented syntax of nftables rules
and set/map elements is implemented by the higher-level APIs, so if we
used the lower-level APIs (or the JSON API, which wraps the
lower-level APIs), then the official nftables documentation would be
mostly useless to people using this library. (You would essentially be
forced to do `nft add rule ...; nft -j list chain ...` to figure out
the JSON syntax for the rules you wanted so you could then write it in
the form the library needed.)

Using the non-JSON syntax has its own problems, and means that it is
basically impossible for us to reliably parse the actual "rule" part
of rules. (We can reliably parse the output of `"nft list chain"` into
`Rule` objects, including distinguishing any `comment` from the rule
itself, but we don't have any ability to split the rule up into
individual clauses.)

The fact that the API uses functions and objects (e.g.
`tx.Add(&nftables.Chain{...})`) rather than just specifying everything
as textual input to `nft` (e.g. `tx.Exec("add chain ...")`) is mostly
just because it's _much_ easier to have a fake implementation for unit
tests this way.
