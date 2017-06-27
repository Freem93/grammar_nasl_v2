#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Nessus is older than 5.2");

include("compat.inc");

if (description)
{
  script_id(73920);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2012-1493", "CVE-2013-3619");
  script_bugtraq_id(53897, 66267, 66268, 66299);
  script_osvdb_id(82780, 99595, 104653, 104666, 104719);
  script_xref(name:"EDB-ID", value:"19091");
  script_xref(name:"EDB-ID", value:"32372");

  script_name(english:"SSH Static Key Accepted");
  script_summary(english:"Checks if static SSH private keys are accepted.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host accepts a static SSH private key
for authentication.");
  script_set_attribute(attribute:"description", value:
"The SSH server on the remote host accepts a publicly known static SSH
private key for authentication. A remote attacker can log in to this
host using this publicly known private key.");
  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.com/files/view/38537/lantronix.txt");
  # http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b739cf7");
  # http://packetstormsecurity.com/files/125801/Array-Networks-vAPV-vxAG-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fa4a9a2");
  script_set_attribute(attribute:"see_also", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  # https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99a8b71e");
  script_set_attribute(attribute:"solution", value:
"Remove the vulnerable public keys from the SSH server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP SSH Private Key Exposure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("ssh_func.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# a list of usernames and ssh public keys to test for
keys = make_list2(
# from http://packetstormsecurity.com/files/view/38537/lantronix.txt
make_list("root", "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA9FZwKSNlfAl72aWewoXE1e8g099yCSqVKGTRWSkOBKV8oqVgX8ryj/adwSLbwxSi8HyLd9AfiNmyyTJ4/ITX4JgpNCcw8k6SNK3HrletSs7z4EGHiYcB25gIgX6fQrnjkm1AP3HXR0Wkeg7B5wFqwqKkNUd/aPhegLxjpufB0g0="),
# from http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html
make_list("root", "ssh-dss AAAAB3NzaC1kc3MAAACBAKwKBw7D4OA1H/uD4htdh04TBIHdbSjeXUSnWJsce8C0tvoB01Yarjv9TFj+tfeDYVWtUK1DA1JkyqSuoAtDANJzF4I6Isyd0KPrW3dHFTcg6Xlz8d3KEaHokY93NOmB/xWEkhme8b7Q0U2iZie2pgWbTLXV0FA+lhskTtPHW3+VAAAAFQDRyayUlVZKXEweF3bUe03zt9e8VQAAAIAEPK1k3Y6ErAbIl96dnUCnZjuWQ7xXy062pf63QuRWI6LYSscm3f1pEknWUNFr/erQ02pkfi2eP9uHl1TI1ql+UmJX3g3frfssLNZwWXAW0m8PbY3HZSs+f5hevM3ua32pnKDmbQ2WpvKNyycKHi81hSI14xMcdblJolhN5iY8/wAAAIAjEe5+0m/TlBtVkqQbUit+s/g+eB+PFQ+raaQdL1uztW3etntXAPH1MjxsAC/vthWYSTYXORkDFMhrO5ssE2rfg9io0NDyTIZt+VRQMGdi++dH8ptU+ldl2ZejLFdTJFwFgcfXz+iQ1mx6h9TPX1crE1KoMAVOj3yKVfKpLB1EkA=="),
# from http://www.exploit-db.com/exploits/32372/
make_list("root", "ssh-dss AAAAB3NzaC1kc3MAAACBAISAE3CAX4hsxTw0dRc0gx8nQ41r3Vkj9OmG6LGeKWRmpy7C6vaExuupjxid76fd4aS56lCUEEoRlJ3zE93qoK9acI6EGqGQFLuDZ0fqMyRSX+ilf+1HDo/TRyuraggxp9Hj9LMpZVbpFATMm0+d9Xs7eLmaJjuMsowNlOf8NFdHAAAAFQCwdvqOAkR6QhuiAapQ/9iVuR0UAQAAAIBpLMo4dhSeWkChfv659WLPftxRrX/HR8YMD/jqa3R4PsVM2g6dQ1191nHugtdV7uaMeOqOJ/QRWeYM+UYwT0Zgx2LqvgVSjNDfdjk+ZRY8x3SmExFi62mKFoTGSOCXfcAfuanjaoF+sepnaiLUd+SoJShGYHoqR2QWiysTRqknlwAAAIBLEgYmr9XCSqjENFDVQPFELYKT7Zs9J87PjPS1AP0qF1OoRGZ5mefK6X/6VivPAUWmmmev/BuAs8M1HtfGeGGzMzDIiU/WZQ3bScLB1Ykrcjk7TOFD6xrnk/inYAp5l29hjidoAONcXoHmUAMYOKqn63Q2AsDpExVcmfj99/BlpQ=="),
# from http://packetstormsecurity.com/files/125801/Array-Networks-vAPV-vxAG-Code-Execution.html
make_list("sync", "ssh-dss AAAAB3NzaC1kc3MAAACBAJTDsX+8olPZeyr58g9XE0L8PKT5030NZBPlE7np4hBqx36HoWarWq1Csn8M57dWN9StKbs03k2ggY6sYJK5AW2EWar70um3pYjKQHiZq7mITmitsozFN/K7wu2e2iKRgquUwH5SuYoOJ29n7uhaILXiKZP4/H/dDudqPRSY6tJPAAAAFQDtuWH90mDbU2L/Ms2lfl/cja/wHwAAAIAMBwSHZt2ysOHCFe1WLUvdwVDHUqk3QHTskuuAnMlwMtSvCaUxSatdHahsMZ9VCHjoQUx6j+TcgRLDbMlRLnwUlb6wpniehLBFk+qakGcREqks5NxYzFTJXwROzP72jPvVgQyOZHWq81gCild/ljL7hmrduCqYwxDIz4o7U92UKQAAAIBmhSl9CVPgVMv1xO8DAHVhM1huIIK8mNFrzMJz+JXzBx81ms1kWSeQOC/nraaXFTBlqiQsvB8tzr4xZdbaI/QzVLKNAF5C8BJ4ScNlTIx1aZJwyMil8Nzb+0YAsw5Ja+bEZZvEVlAYnd10qRWrPeEY1txLMmX3wDa+JvJL7fmuBg=="),
# from https://www.trustmatta.com/advisories/MATTA-2012-002.txt
make_list("root", "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk="),
# from https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities
make_list("root", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC1q1kR6chWLfwspD84Asyy6EFV6SYRGy/gILsYGtn9kCQi2RFobNxS5CvphbGWn9D9n5gJpTVWLWb3LwJxGuBKSRj2wrHLlejzw6kSmF+3xFCuMfxVFSj8TM8JqlOqM1c6lvH2MSXnN7pJBVcekNKbBUEfptakPSejStljbXecSw=="),
# from https://github.com/mitchellh/vagrant/blob/master/keys/vagrant.pub
make_list("vagrant", "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ=="),
# https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys/testing_rsa.pub
make_list("root", "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAvsNpFdK5lb0GfKx+FgsrsM/2+aZVFYXHMPdvGtTz63ciRhq0Jnw7nln1SOcHraSz3/imECBg8NHIKV6rA+B9zbf7pZXEv20x5Ul0vrcPqYWC44PTtgsgvi8s0KZUZN93YlcjZ+Q7BjQ/tuwGSaLWLqJ7hnHALMJ3dbEM9fKBHQBCrG5HOaWD2gtXj7jp04M/WUnDDdemq/KMg6E9jcrJOiQ39IuTpas4hLQzVkKAKSrpl6MY2etHyoNarlWhcOwitArEDwf3WgnctwKstI/MTKB5BTpO2WXUNUv4kXzA+g8/l1aljIG13vtd9A/IV3KFVx/sLkkjuZ7z2rQXyNKuJw== ChromeOS test key")
);

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

unused_dsa_key = "ssh-dss AAAAB3NzaC1kc3MAAACBALU8qVWXxuX5AU02AfOcCntF0aWc27ORBkcoE4ZpwcIUZWOuEzII/u2eqjj5SsryOhCgersaU8c5nwqPDAatqKONr+jdPzfoSIVOexHMQ3jBtdmRiCS/E3jqjzUkEPck+aeme+9xtKSrii+pO5QkCNsCBfASAvW9bMEeadtp2zS/AAAAFQCmQCOuRSlApxWWUTebousceVBahwAAAIAesuQ1Rhq8yfTFqvzAmddk02iLpZB7tIQf0Lh1FPNhtSFC399hZ5x8vq4oy8BWJ614Rvlwm/3CBdkN+zriuCdFJPgc6SgGl4yvcMFRkQWBQvrJTD+LD8/5z2c6vXSLxj+y5WguiTupLoEu0ye6RM+RjGDUE2PWO/I97w93nggN7QAAAIBhFdlk0EYuwhX9VpwtZbCtQdZwyhUCg3gCJ8cGegOdk1iOd44AfQuGilIDjn8+aclUHKhDLLqZwgjPBCbERmQIguwE7Jlfjymc87BxKa8QSi9mymsGh4Qkub3f1iSEjkdcuYfJbl0PTea8lCNoTABdYupecAA0SCCZs42G+GWVjQ==";
unused_rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrhKssa/f/kxvlkDM8po52qo/X8CMa4dFngbYbcHOR7ljH5kGwDS44OE9TZAa51bk+quhW8GPVQbRYz2QB7nxBhYDzmMBBQJS9/LGPCCg9HoEABpKAIb3aG2ZXAHi9rdtRG4GyGi1xxzzxfoBUQjMN4H/PiF+1TOXIW6+G2oGQInHlnHN5I8FVJu3hpXwPiiPWtYWf6hYE7BQ0q2T/sFEyNk3nxYBIQs5kWIxoMVV9Nv1Djp2e2rv9g88N6cj1IGggHhoZ6tv/r+I9svGw7Rf+NP176LRGkCwLb+2FSGkP6jw+u3UCdlkaK/WIb1IANcGPUB/7oj+EiFaY1F3Mzkq5";

sleep(2);
_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);
ret1 = ssh_login_public_key_only(pub:unused_dsa_key, login:"root");
close(_ssh_socket);
if (!ret1)
{
  error = get_ssh_error();
  if (error != "Server did not reply with SSH_MSG_USERAUTH_PK_OK.")
    exit(0, "This SSH server cannot be checked since it is dropping SSH connections.");
}

sleep(2);
_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);
ret2 = ssh_login_public_key_only(pub:unused_rsa_key, login:"root");
close(_ssh_socket);
if (!ret2)
{
  error = get_ssh_error();
  if (error != "Server did not reply with SSH_MSG_USERAUTH_PK_OK.")
    exit(0, "This SSH server cannot be checked since it is dropping SSH connections.");
}

if (ret1 || ret2)
  exit(0, "This SSH server cannot be checked since it always responds with success to a public key user authentication request, regardless of whether or not it actually accepts the public key provided.");

works = "";

foreach pair (keys)
{
  sleep(2);
  # open a new connection for each key as some SSH servers don't let you test more than one key per connection
  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

  user = pair[0];
  key = pair[1];
  ret = ssh_login_public_key_only(pub:key, login:user);
  if (ret)
    works += '\n  User : ' + user +
             '\n  Key  : ' + key +
             '\n';

  close(_ssh_socket);
}

if (works == "") audit(AUDIT_LISTEN_NOT_VULN, "SSH server", port);

if (report_verbosity > 0)
{
  report =
'Nessus was able to verify the following users and public SSH keys\n' +
'(with publicly known private keys) are accepted :\n';
  report = report + works;
  security_hole(port:port, extra:report);
}
else security_hole(port);
