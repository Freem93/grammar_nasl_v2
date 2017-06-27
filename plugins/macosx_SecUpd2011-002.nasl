#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(53412);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/02/06 20:28:42 $");

  script_name(english:"Mac OS X Fraudulent Digital Certificates (Security Update 2011-002)");
  script_summary(english:"Check for the presence of Security Update 2011-002");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes a security
issue."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6 or 10.5 that
does not have Security Update 2011-002 applied. 

A certificate authority (CA) has revoked a number of fraudulent SSL
certificates for several prominent, public websites.  Without this
update, browsers will be unable to learn that the certificates have
been revoked if either Online Certificate Status Protocol (OCSP) is
disabled, or OCSP is enabled and fails. 

If an attacker can trick someone into using the affected browser and
visiting a malicious site using one of the fraudulent certificates, he
may be able to fool that user into believing the site is a legitimate
one.  In turn, the user could send credentials to the malicious site
or download and install applications."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Apr/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2011-002 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(0, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^(9\.[0-8]\.|10\.[0-7]\.)", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2011\.00[2-9]|201[2-9]\.[0-9]+)(\.leopard|\.snowleopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2011-002 or later installed and therefore is not affected.");
  else 
    security_warning(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
