#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were extracted
# from AIX Security PTF U861500. The text itself is copyright (C)
# International Business Machines Corp.
#

include("compat.inc");

if (description)
{
  script_id(87184);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/19 18:41:38 $");

  script_cve_id("CVE-2015-4948", "CVE-2015-5722");

  script_name(english:"AIX 6.1 TL 9 : bos.net.tcp.client (U861500)");
  script_summary(english:"Check for PTF U861500");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is missing AIX PTF U861500, which is related to the
security of the package bos.net.tcp.client.

Product could allow a remote attacker to obtain sensitive information,
caused by a design error when using the SSLv3 protocol. A remote user
with the ability to conduct a man-in-the-middle attack could exploit
this vulnerability via a POODLE (Padding Oracle On Downgraded Legacy
Encryption) attack to decrypt SSL sessions and access the plaintext of
encrypted connections.

Network Time Protocol (NTP) Project NTP daemon (ntpd) is vulnerable to
a denial of service, caused by an error when using symmetric key
authentication. By sending specially crafted packets to both peering
hosts, an attacker could exploit this vulnerability to prevent
synchronization.

The TLS protocol could allow a remote attacker to obtain sensitive
information, caused by the failure to properly convey a DHE_EXPORT
ciphersuite choice. An attacker could exploit this vulnerability using
man-in-the-middle techniques to force a downgrade to 512-bit
export-grade cipher. Successful exploitation could allow an attacker
to recover the session key as well as modify the contents of the
traffic. This vulnerability is commonly referred to as 'Logjam'.

ISC BIND is vulnerable to a denial of service, caused by an error in
the handling of TKEY queries. By sending specially crafted packets, a
remote attacker could exploit this vulnerability to cause a REQUIRE
assertion failure.

IBM AIX could allow a local attacker to escalate their privileges to
root access through a vulnerability in netstat when a fiber channel
adapter is present.

ISC BIND is vulnerable to a denial of service, caused by the exit of a
validating resolver due to an assertion failure in buffer.c. By
parsing a malformed DNSSEC key, a remote attacker could exploit this
vulnerability to cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV73417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV73783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV74916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV74920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV75643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV75692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV75940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IV78091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate missing security-related fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AIX/oslevel", "Host/AIX/version", "Host/AIX/lslpp");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if ( aix_check_patch(ml:"610009", patch:"U861500", package:"bos.net.tcp.client.6.1.9.100") < 0 ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
