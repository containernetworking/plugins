# AKS Integration

# Setup Cluster
```bash
RESOURCE_GROUP=cni-test
CLUSTER_NAME=cni-test

az aks create -l eastus2 \
    --resource-group "${RESOURCE_GROUP}" \
    --cluster-name "${CLUSTER_NAME}" \
    --tier standard \
    --kubernetes-version 1.34.0 \
    --network-plugin none \
    --nodepool-name system \
    --vm-set-type VirtualMachines \
    --node-vm-size Standard_D8ds_v5 \
    --node-count 3
```

# Setup CNI
```bash
python3 setup.py \
  --resource-group "${RESOURCE_GROUP}" \
  --cluster-name "${CLUSTER_NAME}" \
  --ipvlan-prefix-length 28 \
  --boostrap-cni-config
```

# Test CNI
```bash
kubectl apply -f deployment.yaml
```

```bash
kubectl apply -f service.yaml
```