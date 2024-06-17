#### Network File System
NFS is type of file system that enables user to access, view, store and update files over a remote server. Client can access same as it is accessed local  NFS is used for the management of remote file access. This is generally implemented on the computer network, where the centralization of data is required for critical resources

To accomplish the task of sharing files and directories over the network,, the exporting process is used. However the client first attempts to make the file available for sharing by using the mounting process. The "/ect/exports" location on the NFS server contains a list of clients allowed to shared files on the server. In this approach, to access the server, the only credential used is the client's IP address. NFS versions before version 4 run on the same security specification.

By enumeration process of NFS attackers identify the exported directories, list of clients connected to the NFS server, along with their IP addresses, and the shared data associated with the IP addresses and shared data associated with the IP addresses. the attackers can spoof their IP addresses to gain full access to the shared files on the server.
NFS port : 20
further, an attacker can use various other commands and tools to gain access to the NFS server and upload malicious files on the server to launch further attacks



```
rfpcinfo -p 10.10.1.1
```

```
showmount -e 10.10.1.1
```

#### NFS Enumeration Tools
1. RPCScan  source :https://github.com/hegusung/RPCScan , RPCScan communicates with RPC services and checks misconfiguration on NFS shares. 
    `python3 repc-scan.py <targetIPAddress> --rpc`
2. SuperEnum running `./supernum ` th

