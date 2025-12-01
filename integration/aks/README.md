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
Create a deployment with 2 replicas
```bash
kubectl apply -f deployment.yaml
deployment.apps/nginx-lb created

kubectl get pod -l run=nginx-lb -o wide
NAME                        READY   STATUS    RESTARTS   AGE     IP            NODE                        NOMINATED NODE   READINESS GATES
nginx-lb-69c48c6986-8l9gh   1/1     Running   0          2m28s   10.224.0.55   aks-default-42863573-vms3   <none>           <none>
nginx-lb-69c48c6986-bzgvm   1/1     Running   0          2m28s   10.224.0.28   aks-default-42863573-vms1   <none>           <none>
```

Create a service to expose the deployment
```bash
kubectl apply -f service.yaml
service/nginx-svc-lb created

kubectl get service nginx-svc-lb
NAME           TYPE           CLUSTER-IP    EXTERNAL-IP     PORT(S)        AGE
nginx-svc-lb   LoadBalancer   10.0.120.56   68.220.26.204   80:31888/TCP   32s
```
Test pod-to-pod connectivity
```bash
kubectl exec -it  nginx-lb-69c48c6986-bzgvm -- curl 10.224.0.55
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

Test service - DNS and cluster ip
```bash
kubectl exec -it  nginx-lb-69c48c6986-bzgvm -- curl nginx-svc-lb
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

Test egress connectivity
```bash
kubectl exec -it  nginx-lb-69c48c6986-bzgvm -- curl ifconfig.me   
68.220.212.218
```

Test ingress connectivity
```bash
 curl 68.220.26.204
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```