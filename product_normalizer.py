def normalize_product(
    service,
    version
):

    text = (
        f"{service} {version}"
    ).lower()

    # DNS
    if "dnsmasq" in text:
        return "dnsmasq"

    if "isc bind" in text:
        return "bind"

    if "bind" in text:
        return "bind"

    # SSH
    if "openssh" in text:
        return "openssh"

    # FTP
    if "vsftpd" in text:
        return "vsftpd"

    if "proftpd" in text:
        return "proftpd"

    # Apache HTTP Server
    if (
        "apache httpd" in text
        or "apache http server" in text
        or "httpd" in text
    ):
        return "apache http server"

    # Apache Tomcat
    if (
        "tomcat" in text
        or "coyote" in text
        or "apache jserv" in text
    ):
        return "apache tomcat"

    # Databases
    if "mysql" in text:
        return "mysql"

    if "postgresql" in text:
        return "postgresql"

    # File Sharing
    if (
        "samba" in text
        or "smbd" in text
    ):
        return "samba"

    # IRC
    if "unrealircd" in text:
        return "unrealircd"

    # Web Server
    if "nginx" in text:
        return "nginx"

    # distccd
    if "distccd" in text:
        return "distccd"

    # Java RMI
    if (
        "java-rmi" in text
        or "grmiregistry" in text
    ):
        return "java"

    # VNC
    if "vnc" in text:
        return "vnc"

    # RPC
    if "rpcbind" in text:
        return "rpcbind"

    # NFS
    if "nfs" in text:
        return "nfs"

    # Telnet
    if "telnet" in text:
        return "telnet"

    # SMTP
    if (
        "postfix" in text
        or "smtp" in text
    ):
        return "postfix"

    return service.lower()
