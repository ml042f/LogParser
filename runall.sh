#!/bin/bash




./lynis_eval.py $1/os/lynis/lynis.log -b $2 -l
./vuls_eval.py $1/os/vuls/vuls.log -b $2 -l
./kube_eval.py $1/k8s/kube-hunter/Kube-Hunter.Kube-Hunter/cluster.log -b $2 -c -l
./kube_eval.py $1/k8s/kube-hunter/Kube-Hunter.Kube-Hunter/pod.log -b $2 -l