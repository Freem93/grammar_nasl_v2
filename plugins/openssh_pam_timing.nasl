#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") || ! defined_func("unixtime") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(11574);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2016/05/12 14:46:30 $");

 script_cve_id("CVE-2003-0190", "CVE-2003-1562");
 script_bugtraq_id(7342, 7467, 7482, 11781);
 script_osvdb_id(2109, 2140);

 script_name(english:"OpenSSH w/ PAM Multiple Timing Attack Weaknesses");
 script_summary(english:"Checks the timing of the remote SSH server");

 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate valid users on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running an SSH server that could allow an
attacker to determine the existence of a given login by comparing the
time the remote sshd daemon takes to refuse a bad password for a
nonexistent login compared to the time it takes to refuse a bad
password for a valid login.

An attacker could use this flaw to set up a brute-force attack against
the remote host.");
 script_set_attribute(attribute:"solution", value:
"Disable PAM support if you do not use it, upgrade to the OpenSSH
version 3.6.1p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(362);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("ssh_detect.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ssh", 22);

 exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("ssh_func.inc");

if ( get_kb_item("Settings/PCI_DSS") ) banner_chk = TRUE;
if ( supplied_logins_only ) banner_chk = TRUE;

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( banner_chk )
{
 banner = tolower(get_backport_banner(banner:banner));
 if(ereg(pattern:".*openssh[-_](([12]\..*)|(3\.[0-5][^0-9]*)|(3\.6\.[01]$))[^0-9]*",
        string:banner)) {
                security_warning(port);
        }

 exit(0);
}

maxdiff = 3;

if ( ! thorough_tests )
  if ( "openssh" >!<  tolower(banner) ) exit(0);





_ssh_socket = open_sock_tcp(port);
if ( ! _ssh_socket ) exit(0);

then = unixtime();
ret = ssh_login(login:"nonexistent" + rand(), password:"n3ssus");
now = unixtime();
close(_ssh_socket);

inval_diff = now - then;

_ssh_socket = open_sock_tcp(port);
if ( ! _ssh_socket ) exit(0);
then = unixtime();
ret = ssh_login(login:"bin", password:"n3ssus");
now = unixtime();
val_diff = now - then;
if ( ( val_diff - inval_diff ) >= maxdiff ) security_warning(port);
close(_ssh_socket);
