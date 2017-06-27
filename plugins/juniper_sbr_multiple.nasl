#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70165);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2011-4576", "CVE-2011-4619");
  script_bugtraq_id(51281);
  script_osvdb_id(78188, 78190);
  script_xref(name:"IAVA", value:"2013-A-0027");

  script_name(english:"Juniper Steel-Belted Radius Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks version of sbr package");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple OpenSSL vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper Steel-Belted Radius software installed on the
remote RedHat or CentOS host is affected by multiple OpenSSL
vulnerabilities :

  - The SSL 3.0 implementation in OpenSSL does not properly
    initialize data structures for block cipher padding,
    which could allow remote attackers to obtain sensitive
    information by decrypting the padding data sent by an
    SSL peer. (CVE-2011-4576)

  - The Server Gated Cryptography (SGC) implementation in
    OpenSSL does not properly handle handshake restarts,
    which could allow remote attackers to cause a denial of
    service condition. (CVE-2011-4619)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10544");
  script_set_attribute(attribute:"solution", value:"Updates are available from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:juniper:steel-belted_radius");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/RedHat/release");
if (isnull(release)) release = get_kb_item("Host/CentOS/release");

if (isnull(release)) audit(AUDIT_OS_NOT, "Red Hat or CentOS");

if ("Red Hat" >< release)
{
  os = "RedHat";
  rel = "Red Hat";
}
else
{
  os = "CentOS";
  rel = os;
}

rpms = get_kb_item("Host/"+os+"/rpm-list");
if (isnull(rpms)) audit(AUDIT_PACKAGE_LIST_MISSING);

non_vuln = make_list();

package = "sbr-gee";
fixed = "6.1.7";

if (rpm_exists(release:release, rpm:package))
{
  pattern = package + '-([0-9.]+)[-|.].*';
  matches = egrep(pattern:pattern, string:rpms);

  if (!isnull(matches))
  {
    foreach match (split(matches, keep:FALSE))
    {
      rpm = split(match, sep:'|', keep:FALSE);
      if (isnull(rpm[0])) continue;
      rpm = rpm[0];

      version = eregmatch(pattern:pattern, string:rpm);
      if (isnull(version[1])) continue;
      version = version[1];

      if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
        rpm_report_add(package:rpm, reference:package + "-" + fixed);
      else
        non_vuln = make_list(non_vuln, rpm);
    }
  }
}

package = "sbr-ent";
fixed = "6.1.7";

if (rpm_exists(release:release, rpm:package))
{
  pattern = package + '-([0-9.]+)[-|.].*';
  matches = egrep(pattern:pattern, string:rpms);
  if (!isnull(matches))
  {
    foreach match (split(matches, keep:FALSE))
    {
      rpm = split(match, sep:'|', keep:FALSE);
      if (isnull(rpm[0]))
        continue;
      rpm = rpm[0];

      version = eregmatch(pattern:pattern, string:rpm);
      if (isnull(version[1]))
        continue;
      version = version[1];

      if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
        rpm_report_add(package:rpm, reference:package + "-" + fixed);
      else
       non_vuln = make_list(non_vuln, rpm);
    }
  }
}

package = "sbr-spe";
fixed = "7.4.1";

if (rpm_exists(release:release, rpm:package))
{
  pattern = package + '-([0-9.]+)[-|.].*';
  matches = egrep(pattern:pattern, string:rpms);
  if (!isnull(matches))
  {
    foreach match (split(matches, keep:FALSE))
    {
      rpm = split(match, sep:'|', keep:FALSE);
      if (isnull(rpm[0])) continue;
      rpm = rpm[0];

      version = eregmatch(pattern:pattern, string:rpm);
      if (isnull(version[1])) continue;
      version = version[1];

      if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
        rpm_report_add(package:rpm, reference:package + "-" + fixed);
      else
        non_vuln = make_list(non_vuln, rpm);
    }
  }
}

report = rpm_report_get();
if (isnull(report))
{
  if (max_index(non_vuln) == 0)
    audit(AUDIT_PACKAGE_NOT_INSTALLED, "Juniper Steel-Belted Radius");
  if (max_index(non_vuln) == 1)
    audit(AUDIT_PACKAGE_NOT_AFFECTED, non_vuln[0]);

  exit(0, "None of the installed Juniper Steel-Belted Radius packages (" + join(non_vuln, sep:", ") + ") are affected.");
}

if (report_verbosity > 0) security_warning(port:0, extra:report);
else security_warning(0);
