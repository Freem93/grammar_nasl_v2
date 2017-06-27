#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67243);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2013-3969", "CVE-2013-4650");
  script_bugtraq_id(61007, 61309);
  script_osvdb_id(94901, 95507);

  script_name(english:"MongoDB < 2.4.5 / 2.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MongoDB");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of the remote MongoDB server is a version prior to
version 2.4.5 / 2.5.1. It is, therefore, potentially affected by the
following vulnerabilities :

  -  A remote attacker can gain elevated privileges when
     authenticating as the internal __system user name for
     arbitrary databases. (CVE-2013-4650)

  -  The JavaScript engine is vulnerable to a flaw that
     could be triggered remotely to cause a segmentation
     fault, or potentially arbitrary code execution.
     (CVE-2013-3969)"
  );
  # https://github.com/mongodb/mongo/commit/fc9491ee7be6a7dc8a92a8422468284359073545
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dfa8c8f");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-9983");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-9878");
  # https://github.com/mongodb/mongo/commit/fda4a2342614e4ca1fb26c868a5adef0e050eb5e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e66060");
  script_set_attribute(attribute:"see_also", value:"http://blog.scrt.ch/2013/06/04/mongodb-rce-by-databasespraying/");
  script_set_attribute(attribute:"solution", value:"Upgrade to MongoDB 2.4.5 / 2.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Services/mongodb", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "MongoDB";

port = get_service(svc:"mongodb", exit_on_fail:TRUE);

version = get_kb_item_or_exit("mongodb/" + port + "/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "";

# 2.4.x < 2.4.5
if (
  version =~ "^2\.4\.[0-4]($|[^0-9])" ||
  version =~ "^2\.4($|[^.0-9])"
) fix = "2.4.5";

# 2.5.x < 2.5.1
else if (
  version =~ "^2\.5\.0($|[^0-9])" ||
  version =~ "^2\.5($|[^.0-9])"
) fix = "2.5.1";

else audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix + 
           '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
