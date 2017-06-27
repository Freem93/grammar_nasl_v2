#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory7.asc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93350);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:16 $");

  script_cve_id("CVE-2015-7974", "CVE-2016-1547", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4957");

  script_name(english:"AIX 5.3 TL 12 : ntp (IV87614)");
  script_summary(english:"Check for APAR IV87614");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NTPv3 and NTPv4 are vulnerable to :

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7974 NTP could
allow a remote authenticated attacker to conduct spoofing attacks,
caused by a missing key check. An attacker could exploit this
vulnerability to impersonate a peer. NTP could allow a local attacker
to bypass security restrictions, caused by the failure to use a
constant-time memory comparison function when validating the
authentication digest on incoming packets. By sending a specially
crafted packet with an authentication payload, an attacker could
exploit this vulnerability to conduct a timing attack to compute the
value of the valid authentication digest. While the majority OSes
implement martian packet filtering in their network stack, at least
regarding 127.0.0.0/8, a rare few will allow packets claiming to be
from 127.0.0.0/8 that arrive over physical network. On these OSes, if
ntpd is configured to use a reference clock an attacker can inject
packets over the network that look like they are coming from that
reference clock. If ntpd was expressly configured to allow for remote
configuration, a malicious user who knows the controlkey for ntpq or
the requestkey for ntpdc (if mode7 is expressly enabled) can create a
session with ntpd and then send a crafted packet to ntpd that will
change the value of the trustedkey, controlkey, or requestkey to a
value that will prevent any subsequent authentication with ntpd until
ntpd is restarted. NTP is vulnerable to a denial of service, caused by
an error when using a specially crafted packet to create a peer
association with hmode > 7. An attacker could exploit this
vulnerability to cause the MATCH_ASSOC() function to trigger an
out-of-bounds read. NTP is vulnerable to a denial of service, caused
by the failure to always check the ctl_getitem() function return
value. By sending an overly large value, an attacker could exploit
this vulnerability to cause a denial of service. NTP is vulnerable to
a denial of service, caused by the demobilization of a preemptable
client association. By sending specially crafted crypto NAK packets,
an attacker could exploit this vulnerability to cause a denial of
service. NTP is vulnerable to a denial of service, caused by the
improper handling of packets. By sending specially crafted CRYPTO_NAK
packets, an attacker could exploit this vulnerability to cause ntpd to
crash. NTP is vulnerable to a denial of service, caused by the
improper handling of packets. By sending specially crafted CRYPTO_NAK
packets to an ephemeral peer target prior to a response being sent, a
remote attacker could exploit this vulnerability to demobilize the
ephemeral association. NTP is vulnerable to a denial of service,
caused by the improper handling of packets. By sending spoofed server
packets with correct origin timestamps, a remote attacker could
exploit this vulnerability to cause a false leap indication to be set.
NTP is vulnerable to a denial of service, caused by the improper
handling of packets. By sending spoofed CRYPTO_NAK or a bad MAC
packets with correct origin timestamps, a remote attacker could
exploit this vulnerability to cause the autokey association to reset."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp_advisory7.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"5.3", ml:"12", sp:"09", patch:"IV87614m9a", package:"bos.net.tcp.client", minfilesetver:"5.3.12.0", maxfilesetver:"5.3.12.10") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
