# gm
Implement GM sm3/sm2 based on openssl project.
The specifications are <GM/T 0003-2012> and <GM/T 0004-2012>.

You should build your own openssl project, because openssl-devel project 
installed through yum/apt tool may #defined OPENSSL_NO_EC2M macro, 
so F2m group is not supported.

In the older version of openssl(before version 1.0.2), there is no funcs 
to control ECDSA_METHOD struct, so I choose the openssl-1.0.2h version. 

Author: lnwdl (lnwdl@163.com)
