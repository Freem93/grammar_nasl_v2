#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90423);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/24 15:27:28 $");

  script_cve_id(
    "CVE-2016-2193",
    "CVE-2016-3065"
  );
  script_bugtraq_id(
    85784,
    85786
  );
  script_osvdb_id(
    136561,
    136562
  );

  script_name(english:"PostgreSQL 9.5.x < 9.5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.5.x prior
to 9.5.2. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists that is triggered when a query plan is
    incorrectly reused for more than one ROLE within the
    same session. An authenticated, remote attacker can
    exploit this to cause an incorrect set of Row Level
    Security (RLS) policies to be used for the query.
    (CVE-2016-2193)
  
  - A denial of service vulnerability exists within file
    contrib/pageinspect/brinfuncs.c when certain functions
    in the pageinspect extension are used with BRIN index
    pages. An authenticated, remote attacker can exploit
    this, via contrived 'bytea' values, to crash the server
    or disclose a small amount of server memory.
    (CVE-2016-3065)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1656/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-5-2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected : 9.5.x < 9.5.2
if (ver[0] == 9 && ver[1] == 5 && ver[2] < 2)
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.5.2\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
