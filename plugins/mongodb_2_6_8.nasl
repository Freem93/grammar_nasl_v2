#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88931);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/25 16:05:29 $");

  script_cve_id("CVE-2015-1609");
  script_bugtraq_id(72990);
  script_osvdb_id(118815);

  script_name(english:"MongoDB 2.4.x < 2.4.13 / 2.6.x < 2.6.8 / 3.0.x < 3.0.0-rc9 mongod BSON DoS");
  script_summary(english:"Checks the version of MongoDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 2.4.x prior to 2.4.13 or
2.6.x prior to 2.6.8 or 3.0.x prior to 3.0.0-rc9. It is, therefore,
affected by a denial of service vulnerability in mongod due to
improper validation of BSON messages. A remote, unauthenticated
attacker can exploit this, via a specially crafted BSON message, to
cause an uncaught exception, resulting in a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-17264");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/alerts");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 2.4.13 / 2.6.8 / 3.0.0-rc9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Services/mongodb", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "MongoDB";

port = get_service(svc:"mongodb", exit_on_fail:TRUE);

disp_version = get_kb_item_or_exit("mongodb/" + port + "/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (disp_version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "MongoDB", port);

version = disp_version;
rc = -1;

if (disp_version =~ "-rc")
{
  version = substr(disp_version, 0, stridx(disp_version, "-rc") - 1);
  rc = substr(disp_version, stridx(disp_version, "-rc") + 3);
}

# affected: 2.6.7 and earlier, 2.4.12 and earlier, 3.0.0-rc8 and earlier
# fixed: 2.6.8, 2.4.13, 3.0.0-rc9
# "All MongoDB production releases up to 2.6.7 are affected by this issue."
# so if we aren't 2.4.X or 3.0.x, we check against 2.6.8.
fix_rc = -1;
if (version =~ "^2\.4\.")
{
  fix = "2.4.13";
  disp_fix = fix;
}
else if (version =~ "^3\.0\.")
{
  fix = "3.0.0";
  disp_fix = "3.0.0-rc9";
  fix_rc = "9";
}
else
{
  fix = "2.6.8";
  disp_fix = fix;
}

vuln = FALSE;

# no rcs involved at all
# flag when version >= fix
if (rc == -1 && fix_rc == -1)
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    vuln = TRUE;

# rc in ver, but not fix
# flag when version > fix
if (rc > -1 && fix_rc == -1)
  if (ver_compare(ver:version, fix:fix, strict:FALSE) <= 0)
    vuln = TRUE;

# rc in fix, but not ver
# flag when version >= fix
if (rc == -1 && fix_rc > -1)
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    vuln = TRUE;

# rc in both
# flag when version == fix and rc >= fix_rc
if (rc > -1 && fix_rc > -1)
  if (version == fix)
    if (ver_compare(ver:rc, fix:fix_rc) < 0 )
      vuln = TRUE;

if (vuln)
{
  report = '\n  Installed version : ' + disp_version +
           '\n  Fixed version     : ' + disp_fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, disp_version);
