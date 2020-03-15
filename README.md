```
sudo tc qdisc add dev ens3 ingress handle ffff:
sudo tc filter add dev ens3 parent ffff: bpf obj badarp.o sec classifier flowid ffff:1 action bpf obj badarp.o sec action ok
sudo tc exec bpf dbg
```
