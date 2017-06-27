#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Nessus is older than 5.2");

include("compat.inc");

if (description)
{
  script_id(84501);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2015-4216");
  script_osvdb_id(123705);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu95988");
  script_xref(name:"IAVA", value:"2015-A-0136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu95994");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu96630");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150625-ironport");

  script_name(english:"Cisco Ironport Security Appliance Authorized Key Vulnerability");
  script_summary(english:"Checks if the remote host responds to a known public key.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco security appliance contains a default entry in the
authorized_keys file. This allows an attacker with knowledge of the
private key to connect to the system with privileges of the root user.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150625-ironport
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b60640b6");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory                 
cisco-sa-20150625-ironport.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_virtual_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);


unused_dsa_key = "ssh-dss AAAAB3NzaC1kc3MAAACBALU8qVWXxuX5AU02AfOcCntF0aWc27ORBkcoE4ZpwcIUZWOuEzII/u2eqjj5SsryOhCgersaU8c5nwqPDAatqKONr+jdPzfoSIVOexHMQ3jBtdmRiCS/E3jqjzUkEPck+aeme+9xtKSrii+pO5QkCNsCBfASAvW9bMEeadtp2zS/AAAAFQCmQCOuRSlApxWWUTebousceVBahwAAAIAesuQ1Rhq8yfTFqvzAmddk02iLpZB7tIQf0Lh1FPNhtSFC399hZ5x8vq4oy8BWJ614Rvlwm/3CBdkN+zriuCdFJPgc6SgGl4yvcMFRkQWBQvrJTD+LD8/5z2c6vXSLxj+y5WguiTupLoEu0ye6RM+RjGDUE2PWO/I97w93nggN7QAAAIBhFdlk0EYuwhX9VpwtZbCtQdZwyhUCg3gCJ8cGegOdk1iOd44AfQuGilIDjn8+aclUHKhDLLqZwgjPBCbERmQIguwE7Jlfjymc87BxKa8QSi9mymsGh4Qkub3f1iSEjkdcuYfJbl0PTea8lCNoTABdYupecAA0SCCZs42G+GWVjQ==";
unused_rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrhKssa/f/kxvlkDM8po52qo/X8CMa4dFngbYbcHOR7ljH5kGwDS44OE9TZAa51bk+quhW8GPVQbRYz2QB7nxBhYDzmMBBQJS9/LGPCCg9HoEABpKAIb3aG2ZXAHi9rdtRG4GyGi1xxzzxfoBUQjMN4H/PiF+1TOXIW6+G2oGQInHlnHN5I8FVJu3hpXwPiiPWtYWf6hYE7BQ0q2T/sFEyNk3nxYBIQs5kWIxoMVV9Nv1Djp2e2rv9g88N6cj1IGggHhoZ6tv/r+I9svGw7Rf+NP176LRGkCwLb+2FSGkP6jw+u3UCdlkaK/WIb1IANcGPUB/7oj+EiFaY1F3Mzkq5";

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);
ret1 = ssh_login_public_key_only(pub:unused_dsa_key, login:"service");
close(_ssh_socket);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);
ret2 = ssh_login_public_key_only(pub:unused_rsa_key, login:"service");
close(_ssh_socket);

if (ret1 || ret2)
  exit(0, "This SSH server cannot be checked since it always responds with success to a public key user authentication request, regardless of whether or not it actually accepts the public key provided.");

# cisco tech support account
user = "service";

# static public key
key = "ssh-dss AAAAB3NzaC1kc3MAAACBAKlMl4beBf/JD4F5sNym0l5LDRMWhHhH7oKyJPWzvSi/DjVJ6HWQnhPp3aq2CORtpd6yO8tExXDRx5VBzI2slBCi+rIaQ6sWr4Ie/aAr/FdXycbPdeKxwHawQr5esqeWb0+z59wDzSOblAx4R1JfE2HdLcRPx9GhGjHx55T+qZVtAAAAFQDuNCywyl6f57Wa48+YX2Kk86dw1QAAAIB4vpeYVOZ+6T9ohXuJajRQ8dxgID40cvxGnz3je2Y9EO7fY8gtFai8mojih2Mbkbt6fdpS+mWEDIIQAjLNi75ih/ONz8OfBzvkUznAcHjRTHrW7tSJ3Xtkpx02ddT/bDQRLIj5/V8/vY9Wsuf+l7h/7LvzXCZOo1IAILnpogK1ggAAAIEAket7Jq8HFSyp3NTlZdQNeOB0K46VK7X1I8YzHfdILeAoXxNqFWEvhB50iHw1390ETx3J9luGHtOze9JeAFr+m2HrkltfTwvUwyxbjX0yAHsXWvQ5xwXhpV0nm1hOhxHg60/5QfXu75ZKhEAz/ZWKkteK0na+mWbFAnKMUG04TwI=";

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

ret = ssh_login_public_key_only(pub:key, login:user);

close(_ssh_socket);

if (ret)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify that the remote host accepts the following' +
      '\nuser account and public key combination :' +
      '\n  User : ' + user +
      '\n  Key  : ' + key +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SSH server", port);
