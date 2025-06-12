#Read this before setting up cluster 
#https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
sudo apt update && sudo apt upgrade -y
 sudo apt install net-tools
#Helps you inspect network interfaces, check IP addresses, or troubleshoot cluster networking 
ifconfig -a
#Kubernetes does not support swap. kubeadm init and kubelet will fail if swap is enabled because it can break pod scheduling and resource guarantees
#Swap memory is a portion of the hard disk (or SSD) that is used as virtual RAM when your system runs out of physical RAM (Random Access Memory).

sudo swapoff -a

#disable swap permanently so that it doesn't get enabled after reboot:-
	#Now this "
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
#means:- Comment out swap line in /etc/fstab which can also be done by:-
#Optional
sudo vim /etc/fstab

6. sysctl params required by setup, params persist across reboots
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF


#Add these commands to set hostnames:-
sudo apt update && sudo apt upgrade -y

sudo hostnamectl set-hostname master   # on master
sudo hostnamectl set-hostname worker1  # on worker 1
sudo hostnamectl set-hostname worker2  # on worker 2

#On all three nodes:
sudo nano /etc/hosts
#Add:
#YourMachinePrivateIp172.31.46.56  master
#YourMachinePrivateIp172.31.7.48 worker1
#YourMachinePrivateIp172.31.6.253 worker2


#This command sets kernel parameters required by Kubernetes for proper network packet forwarding and filtering.

# 6. sysctl params required by setup, params persist across reboots
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF


# Apply sysctl params without reboot
#These settings are saved in /etc/sysctl.d/k8s.conf and persist across reboots. 

sudo sysctl --system


# Verify that the br_netfilter, overlay modules are loaded by running the following commands:
lsmod | grep br_netfilter
lsmod | grep overlay

#All three modules are correctly loaded — you're ready for pod networking and containerized workloads in Kubernetes.

# Verify that the net.bridge.bridge-nf-call-iptables, net.bridge.bridge-nf-call-ip6tables, and net.ipv4.ip_forward system variables are set to 1 in your sysctl config by running the following command:

sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward

# Apply sysctl params without reboot
sudo sysctl --system


#Verify that net.ipv4.ip_forward is set to 1 with:

	sysctl net.ipv4.ip_forward


#Install containerd as standalone not from docker because it will complicate everything for Kubernetes.

#Go to this website:- https://kubernetes.io/docs/setup/production-environment/container-runtimes/
#and then this repo:-
#https://github.com/containerd/containerd/blob/main/docs/getting-started.md
#Click getting started,After that check about containerd latest version on github page 

VERSION=2.1.1     #containerdversion
OS=linux                 #operatingsystem
ARCH=amd64         #system_architecture_whichis_x86_64

# Download the tar.gz archive
curl -LO https://github.com/containerd/containerd/releases/download/v$VERSION/containerd-$VERSION-$OS-$ARCH.tar.gz

# Download the sha256sum file
curl -LO https://github.com/containerd/containerd/releases/download/v$VERSION/containerd-$VERSION-$OS-$ARCH.tar.gz.sha256sum

# Verify the SHA256 checksum
sha256sum -c containerd-$VERSION-$OS-$ARCH.tar.gz.sha256sum

# Extract to /usr/local
sudo tar Cxzvf /usr/local containerd-$VERSION-$OS-$ARCH.tar.gz

 

#these commands download containerd according to latest version and operating system and extract it into local usr 

#To start containerd we need to install systemd
https://github.com/containerd/containerd/blob/main/docs/getting-started.md

# Create the target directory if it doesn't exist
sudo mkdir -p /usr/local/lib/systemd/system

# Download the containerd systemd service file
sudo curl -Lo /usr/local/lib/systemd/system/containerd.service https://raw.githubusercontent.com/containerd/containerd/main/containerd.service

# Reload systemd to recognize the new service file
sudo systemctl daemon-reload

# Enable containerd to start on boot, and start it now
sudo systemctl enable --now containerd


#Installing runc
#https://github.com/opencontainers/runc/releases

#Download the runc.<ARCH> binary from https://github.com/opencontainers/runc/releases , verify its sha256sum, and install it as /usr/local/sbin/runc. Take the version from latest release and ARCH=system cpu
#These commands download and install runc, a low-level container runtime used by containerd to create and manage containers.
#It installs the binary as /usr/local/sbin/runc with executable permissions, allowing Kubernetes to run containers via containerd.


curl -LO https://github.com/opencontainers/runc/releases/download/v1.3.0/runc.amd64

sudo install -m 755 runc.amd64 /usr/local/sbin/runc


#Installing CNI plugins
#Download the cni-plugins-<OS>-<ARCH>-<VERSION>.tgz archive from #https://github.com/containernetworking/plugins/releases , verify its sha256sum, and extract it under /opt/cni/bin:

#These commands install CNI (Container Network Interface) plugins, which are essential for Kubernetes networking.

#change the version and system arch 
curl -LO https://github.com/containernetworking/plugins/releases/download/v1.7.1/cni-plugins-linux-amd64-v1.7.1.tgz

sudo mkdir -p /opt/cni/bin

sudo tar -C /opt/cni/bin -xzvf cni-plugins-linux-amd64-v1.7.1.tgz

#Now come back to this website:-

#https://kubernetes.io/docs/setup/production-environment/container-runtimes/
and first make directory by running these commands:-
#now we need to tell containerd about we are using systemd as runtime driver 

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

#Modifies the config to use systemd as the cgroup driver instead of cgroupfs

sudo sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml

sudo systemctl daemon-reload
sudo systemctl enable --now containerd

#becuase cgroup is older method  to manage container runtime which because default 

# Check that containerd service is up and running
sudo systemctl restart containerd
sudo systemctl status containerd


#Install kubeadm , (kubernetes admin)
13. Now all these setup is done and come back to this kubeadm page to install kubeadm, kubelet, kubectl:- https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
 
#These instructions are for Kubernetes v1.32.

#Update the apt package index and install packages needed to use the Kubernetes apt repository:

 sudo apt-get update
 
# apt-transport-https may be a dummy package; if so, you can skip that package
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

#Download the public signing key for the Kubernetes package repositories. The same signing key is used for all repositories so you can disregard the version in the URL:

# If the directory `/etc/apt/keyrings` does not exist, it should be created before the curl command, read the note below.
 
# sudo mkdir -p -m 755 /etc/apt/keyrings

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

#Note:In releases older than Debian 12 and Ubuntu 22.04, directory /etc/apt/keyrings does not exist by default, and it should be created before the curl command.

 #Add the appropriate Kubernetes apt repository. Please note that this repository have packages only for Kubernetes 1.32; for other Kubernetes minor versions, you need to change the Kubernetes minor version in the URL to match your desired minor version (you should also check that you are reading the documentation for the version of Kubernetes that you plan to install).

# This overwrites any existing configuration in /etc/apt/sources.list.d/kubernetes.list
 echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

#Update the apt package index, install kubelet, kubeadm and kubectl, and pin their version:

    sudo apt-get update
    sudo apt-get install -y kubelet kubeadm kubectl
    sudo apt-mark hold kubelet kubeadm kubectl

  #(Optional) Enable the kubelet service before running kubeadm:

    sudo systemctl enable --now kubelet

ONLY ON MASTER NODE 
sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --apiserver-advertise-address=<Private-IP-Master> --node-name master-node

#When you do it you will see the commands below after kubeadm init copy and paste it 
#Run these commands generated from above:-
  
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

export KUBECONFIG=/etc/kubernetes/admin.conf


#Worker Node 
#copy the output and paste it into worker node with port number aslo like 

 #Copy this command generated to run to worker nodes to join to master:-
	sudo kubeadm join 172.31.41.140:6443 --token uxak94.p2oguv5hdf424ni3 --discovery-token-ca-cert-hash sha256:be4999c3302ba0b719786f343f18a7e8f458a483dbffd4402b54911b9b19085e

#You can re generate the above command by:-
	kubeadm token create --print-join-command
#Installing flannel ONLY ON MASTER
#Flannel is a simple and popular CNI (Container Network Interface) plugin for Kubernetes. It creates a virtual overlay network so that pods across different nodes can communicate with each other.
#Install Calico/Flannel on master node to interact with worker-nodes:-
#First download Flannel manifests:-
	curl -LO https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
	
	sudo vim kube-flannel.yml
#Find the section that looks like this (towards the bottom, under the ConfigMap named kube-flannel-cfg):

#Replace 10.244.0.0/16 with your custom CIDR (192.168.0.0/16) same one when you have given in kubeadm init --pod-network-cidr:
#we have given 192.168.0.0

#Apply the updated Flannel manifest:-	
kubectl apply -f kube-flannel.yml
	
#Verify Flannel is running

#Check the status of the Flannel pods:

kubectl get pods -n kube-flannel
	
#if the flannel pod failed then 
#kubectl describe pod kube-flannel-ds-rrm5h -n kube-flannel
 
# Fix: Load the br_netfilter Kernel Module
# Load the module now
sudo modprobe br_netfilter

# Make it persistent across reboots
echo 'br_netfilter' | sudo tee /etc/modules-load.d/k8s.conf

# Enable bridge-nf-call-iptables
echo 'net.bridge.bridge-nf-call-iptables = 1' | sudo tee /etc/sysctl.d/k8s.conf
sudo sysctl --system

kubectl delete pod pod_name

kubectl get pods -n kube-flannel

#one of the Flannel pods is working (Running), but two are stuck in CrashLoopBackOff. This likely means:
#You’ve added 2 additional worker nodes, and

#Those nodes are missing the required kernel config or modules (like br_netfilter), similar to what you fixed on the master node.
#put same commands to these nodes and delete the pods and check it again 
 

#NOW CHECK NODE 
kubectl get nodes
After successfully getting nodes and everything setup, deploy nginx:-
21. sudo vim nginx-deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80

kubectl apply -f nginx-deployment.yaml

confirm with:-
kubectl get pods -w

kubectl get pods -o wide


22. sudo vim nginx-service.yaml

apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  type: LoadBalancer
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80

kubectl apply -f nginx-service.yaml
kubectl get svc nginx-service


#Install MetalLB:
#To get external ip address for our services 
#self managed Load Balancer like on AWS, Azure because then it would have CCM and self managed to give external IP and you just needed to create ALB and assign the master-node IP as target groups.

#Since it is on bare metal you need to install Metal LB then it will assign and create external IP so that you can have access on it. 
#Install MetalLB:
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.10/config/manifests/metallb-native.yaml

#Now note down public and private IP of all your nodes and also cidr range of subnet:-

#My case public ip address
#master node : public ip address 13.40.25.222     private ip address 172.31.20.91  
#Worker node1 : public ip address 35.176.196.207   private ip address 172.31.26.84
#Worker node2 : public ip address 35.179.146.157    private ip address 172.31.29.234


#We'll pick a small unused range from your subnet — say:
#172.31.30.240 - 172.31.30.250


#This range:

#Is within your 172.31.32.0/20 subnet.

#Won’t overlap with your current node private IPs.

#Should be reachable by the nodes internally (important for L2 mode).




sudo vim metallb-config.yaml


apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: my-ip-pool
  namespace: metallb-system
spec:
  addresses:
  - 172.31.30.240 - 172.31.30.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2adv
  namespace: metallb-system


#Apply the config:-
kubectl apply -f metallb-config.yaml


#Redeploy nginx service:-
kubectl apply -f nginx-service.yaml
kubectl get svc



kubectl port-forward svc/nginx-service 8080:80

#Make sure that 32053 port is open for master-node in security group for all custom ip and anywhere ipv4.
#Access the nginx on public ip of master node:-
http://13.40.25.222:31536/

Cluster is set up and tested now working on 2 layer policy

Install Istio 

# Download Istio
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.18.2 sh -
cd istio-1.18.2
export PATH=$PWD/bin:$PATH
# Install Istio with demo profile
istioctl install --set profile=demo -y
# Enable sidecar injection
kubectl label namespace default istio-injection=enabled
Deploy Google Boutique App
# Clone the repo
git clone https://github.com/GoogleCloudPlatform/microservices-demo.git
cd microservices-demo
# Deploy the app
kubectl apply -f release/kubernetes-manifests.yaml
# Verify
kubectl get pods

kubectl get svc



#Label your service for workflow 
# shopping workflow
kubectl label deployment frontend workflow=shopping
kubectl label deployment cartservice workflow=shopping
kubectl label deployment checkoutservice workflow=shopping
kubectl label deployment paymentservice workflow=shopping

# catalog workflow
kubectl label deployment productcatalogservice workflow=catalog
kubectl label deployment recommendationservice workflow=catalog
kubectl label deployment currencyservice workflow=catalog

# support workflow
kubectl label deployment emailservice workflow=support
kubectl label deployment shippingservice workflow=support

# infra workflow
kubectl label deployment redis-cart workflow=infra
kubectl label deployment adservice workflow=infra
kubectl label deployment loadgenerator workflow=infra


#For Monitering install grafana , prometheus , kiali |  Install Istio Observability Add-ons
cd istio-1.18.2
kubectl apply -f samples/addons

Expose Frontend via Istio Gateway
cat <
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: boutique-gateway
  namespace: default
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: boutique-vs
  namespace: default
spec:
  hosts:
  - "*"
  gateways:
  - boutique-gateway
  http:
  - route:
    - destination:
        host: frontend
        port:
          number: 80
EOF


Install OPA Gatekeeper

kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml
 
#Apply Gatekeeper Policy (Require workflow Label)

# ConstraintTemplate
cat <
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          not input.review.object.metadata.labels["workflow"]
          msg := "Workflow label is required"
        }
EOF
# Constraint
cat <
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-workflow-label
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
EOF

#Test Gatekeeper Policy
# Should fail
cat <
apiVersion: v1
kind: Pod
metadata:
  name: badpod
spec:
  containers:
    - name: nginx
      image: nginx
EOF
# Should succeed
cat <
apiVersion: v1
kind: Pod
metadata:
  name: goodpod
  labels:
    workflow: test
spec:
  containers:
    - name: nginx
      image: nginx
EOF


#BAD POD 
 

#GOOD POD is created 

 

#Apply Istio AuthorizationPolicies

apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: combined-access-policy
  namespace: default
spec:
  selector:
    matchLabels:
      app: cartservice
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/default/sa/frontend
  - from:
    - source:
        principals:
        - cluster.local/ns/default/sa/checkoutservice
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-checkout-to-payment
  namespace: default
spec:
  selector:
    matchLabels:
      app: paymentservice
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/default/sa/checkoutservice




 

#Gateway and VirtualService Configuration
#Istio needs a Gateway and VirtualService to route external traffic from the ingress gateway to the frontend service

apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: frontend-gateway
  namespace: default
spec:
  selector:
    istio: ingressgateway # use istio ingress gateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: frontend-vs
  namespace: default
spec:
  hosts:
  - "*"
  gateways:
  - frontend-gateway
  http:
  - match:
    - uri:
        prefix: /product
    route:
    - destination:
        host: frontend
        port:
          number: 80




#Apply peerauth policy for service to service communictation 
# Strict mTLS for workloads (default namespace):
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default-strict
  namespace: default
spec:
  mtls:
    mode: STRICT

#. Disable mTLS on the ingress gateway namespace (usually istio-system):
#If you don’t disable mTLS on the ingress gateway, it will expect secure mTLS connections, so normal HTTP requests from outside will be blocked. Disabling mTLS on the ingress lets external clients connect normally while keeping internal service communication secure.

apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: ingress-disable-mtls
  namespace: istio-system
spec:
  mtls:
    mode: DISABLE

#Test 
kubectl get peerauthentication --all-namespaces

 

#Test istio authorization policy 
vi test-client.yaml

apiVersion: v1
kind: Pod
metadata:
  name: test-client
  namespace: default
  labels:
    workflow: test
spec:
  containers:
    - name: curl
      image: curlimages/curl
      command: ["sleep", "3600"]
  serviceAccountName: default  # Important: not 'frontend'

kubectl apply -f test-client.yaml


#this policy even pass the workflow barrier from gatekeeper policy because it has workflow labal 

#now test service is created and try to connect the cartservice 

kubectl exec -it test-client -- curl -s -o /dev/null -w "%{http_code}\n" http://cartservice:7070


 

#got 403 forbidden error 


#SSH into EC2 with Local Port Forwarding:
#you can get this url on aws
#run this command 

ssh -i "OPA.pem" \
  -L 20001:localhost:20001 \
  -L 3000:localhost:3000 \
  -L 9090:localhost:9090 \
  -L 16686:localhost:16686 \
ubuntu@ec2-18-130-214-152.eu-west-2.compute.amazonaws.com

ssh -i "C:\Users\bilal\Downloads\OPA.pem" -L 3000:localhost:3000 -L 9090:localhost:9090 -L 16686:localhost:16686 -L 20001:localhost:20001 ubuntu@ec2-18-130-214-152.eu-west-2.compute.amazonaws.com

ssh -i "OPA.pem" -L 3000:localhost:3000 -L 9090:localhost:9090 -L 20001:localhost:20001 -L 16686:localhost:16686 ubuntu@18.130.214.152



#Leave this SSH session open.
#on other Session 

ssh -i "OPA.pem" ubuntu@ec2-18-130-214-152.eu-west-2.compute.amazonaws.com


#Access Dashboards monitoring tools 

# Kiali
kubectl port-forward svc/kiali -n istio-system 20001:20001
# Grafana
kubectl port-forward svc/grafana -n istio-system 3000:3000
# Prometheus
kubectl port-forward svc/prometheus -n istio-system 9090:9090
# Jaeger
kubectl port-forward svc/jaeger-query -n istio-system 16686:16686
#Kiali monitoring  
#access
#🔍 Kiali: http://localhost:20001

]#📊 Grafana: http://localhost:3000

#📈 Prometheus: http://localhost:9090

#🧭 Jaeger (via tracing svc): http://localhost:16686


# secure-poc
