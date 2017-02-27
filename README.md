# oictoolkit



To build docker image

```
bin/build.sh
```

```
kubectl apply -f etc-kube/objects.yaml
gcloud compute firewall-rules create oictoolkit --allow=tcp:30601

```

Generating a RSA keypair:

```
cd var

openssl genrsa -out root.key 2048
openssl rsa -pubout -in root.key -out root.pem

openssl genrsa -out fo.key 2048
openssl rsa -pubout -in fo.key -out fo.pem

openssl genrsa -out entity.key 2048
openssl rsa -pubout -in entity.key -out entity.pem

openssl genrsa -out of.key 2048
openssl rsa -pubout -in of.key -out of.pem

openssl genrsa -out kalmar.key 2048
openssl rsa -pubout -in kalmar.key -out kalmar.pem
```
