#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2819. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71497);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/22 21:33:41 $");

  script_xref(name:"DSA", value:"2819");

  script_name(english:"Debian DSA-2819-1 : iceape End-of-Life Announcement");
  script_summary(english:"Checks dpkg output for the package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host has a package that is no longer supported."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security support for Iceape, the Debian-branded version of the
SeaMonkey suite needed to be stopped before the end of the regular
security maintenance life cycle."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2819"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"We recommend to migrate to Iceweasel for the web browser
functionality and to Icedove for the e-mail bits.  Iceweasel and
Icedove are based on the same codebase and will continue to be
supported with security updates.  Alternatively you can switch to the
binaries provided by Mozilla available at
http://www.seamonkey-project.org/releases/"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


packages = get_kb_item_or_exit("Host/Debian/dpkg-l");
pkg_name = 'iceape';

installed = egrep(string:packages, pattern:'^ii +'+pkg_name+' +');
if (!installed) audit(AUDIT_PACKAGE_NOT_INSTALLED, pkg_name);

version = ereg_replace(string:installed, replace:"\1", pattern: '^ii +'+pkg_name+' +([^ ]+) +.*$');
if (version == installed) version = "";

if (version && report_verbosity > 0)
{
  report = '\n  Installed package : ' + pkg_name + '_' + version +
           '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
