#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(44340);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2017/05/08 18:22:10 $");

 script_name(english:"CentOS Update Set");
 script_summary(english:"Check for CentOS release number.");

 script_set_attribute(attribute:"synopsis", value:
"The remote CentOS operating system is out-of-date.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a release of CentOS that is not at the
latest Update Set. Since updating CentOS brings a host up to the most
recent Update Set, this means that it has not been updated recently,
and is likely to be affected by multiple vulnerabilities.");
 # https://www.centos.org/docs/5/html/Deployment_Guide-en-US/ch-security-updates.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8415728");
 script_set_attribute(attribute:"solution", value:"Apply the latest Update Set.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/CentOS/release", "Host/CentOS/rpm-list");
 exit(0);
}

include("audit.inc");

lastupdate[3] = 9;
lastupdate[4] = 9;
lastupdate[5] = 11;
lastupdate[6] = 7;
lastupdate[7] = 2;

rel = get_kb_item("Host/CentOS/release");
if (! rel)
{
  buf = get_kb_item("Host/CentOS/rpm-list");
  if (!buf) audit(AUDIT_PACKAGE_LIST_MISSING, "rpm");

  buf = egrep(string: buf, pattern: "^centos-release-[0-9]");
  if (! buf) audit(AUDIT_PACKAGE_NOT_INSTALLED, "centos-release");

  v = eregmatch(string: buf, pattern: "centos-release-([0-9.-]+)");
  if (isnull(v)) exit(1, "Could not parse centos-release version ("+buf+").");
  rel = v[1];
}

v = eregmatch(string: rel, pattern: "([0-9]+)[.-]([0-9]+)");
if (isnull(v)) audit(AUDIT_VER_FORMAT, rel);
release = int(v[1]);
updatelevel = int(v[2]);

if (isnull(lastupdate[release]))
  exit(1, "Unknown updatelevel for release '"+release+"'.");

if (updatelevel < lastupdate[release])
{
  str =
    '\n  Installed version : ' + release + '.' + updatelevel +
    '\n  Latest version    : ' + release + '.' + lastupdate[release] +
    '\n';
  security_hole(port:0, extra: str);
  exit(0);
}
else exit(0, "The host is running CentOS "+release+"."+updatelevel+", which is the latest update release for CentOS "+release+".x.");
