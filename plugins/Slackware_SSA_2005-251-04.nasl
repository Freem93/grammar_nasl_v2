#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-251-04. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19863);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/04/12 23:38:29 $");

  script_cve_id("CVE-2005-2491", "CVE-2005-2498");
  script_bugtraq_id(14620);
  script_xref(name:"SSA", value:"2005-251-04");

  script_name(english:"Slackware 10.1 : php5 in Slackware 10.1 (SSA:2005-251-04)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new php5 package is available for Slackware 10.1 in /testing to fix
security issues. PHP has been relinked with the shared PCRE library to
fix an overflow issue with PHP's builtin PRCE code, and PEAR::XMLRPC
has been upgraded to version 1.4.0 which eliminates the eval()
function. The eval() function is believed to be insecure as
implemented, and would be difficult to secure. Note that this new
package now requires that the PCRE package be installed, so be sure to
get the new package from the patches/packages/ directory if you don't
already have it."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.417239
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a6e7a6d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (slackware_check(osver:"10.1", pkgname:"php", pkgarch:"i486", pkgver:"5.0.5", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
