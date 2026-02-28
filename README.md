<p align="center">
    <picture>
        <img src="./src/img/craken_husk.png" alt="BloodPengu.py" width='150'/>
    </picture>
</p>

<hr/>

# gxc-BloodPengu.py

![Python 3 compatible](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/badge/license-Apache_License_2.0-blue)

Data ingestor in Python for `BloodPengu` APM [Attack Path Manager!]

Enumerate via SSH logon authentication and runs the full BloodPengu enumeration pipeline. All output lands on the attacker machine as JSON file, ready to import directly into BloodPengu.

## Features

What it collects over SSH (for BloodPengu):

- users
- sudo `rules`
- SUID
- groups
- services
- cron
- kernel
- `containers:` Docker socket, in-container detection, AWS/GCP/K8s creds
- network interfaces
- env

Extra module with `-M`

- sacspengu mode

## Install

Paramiko

```
pip3 install .
```

```
pip3 install paramiko
```

GitHub Clone

```
git clone https://github.com/byt3n33dl3/gxc-BloodPengu.py.git
```

## LICENSE

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.
```

## CONTACT

For more, come to the documentation for use cases and write-ups [here](https://pengu-apm.github.io/), if there's any security concern, please contact me at <byt3n33dl3@pm.me>