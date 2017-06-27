#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97435);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/02 14:41:04 $");

  script_osvdb_id(
    152268,
    152269,
    152270
  );

  script_name(english:"PostgreSQL 9.2.x < 9.2.20 / 9.3.x < 9.3.16 / 9.4.x < 9.4.11 / 9.5.x < 9.5.6 / 9.6.x < 9.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.2.x prior
to 9.2.20, 9.3.x prior to 9.3.16, 9.4.x prior to 9.4.11, 9.5.x prior
to 9.5.6, or 9.6.x prior to 9.6.2. It is, therefore, affected by
multiple vulnerabilities :

  - An off-by-one buffer overflow condition exists in the
    quote_literal_cstr() function due to improper validation
    of certain input when it is encased entirely in single
    quotes or backslashes. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 152268)

  - A flaw exists when handling multiple concurrent calls of
    the pg_strat_backup() and pg_stop_backup() functions.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 152269)

  - An off-by-one buffer overflow condition exists due to
    improper validation of certain input when handling a
    filename supplied to ecpg that ends with a dot. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or potentially the
    execution of arbitrary code. (VulnDB 152270)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1733/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-2-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-3-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-4-11.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-5-6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/static/release-9-6-2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.2.20 / 9.3.16 / 9.4.11 / 9.5.6 /
9.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 20) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 16) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 11) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 6) ||
  (ver[0] == 9 && ver[1] == 6 && ver[2] < 2)
)
{
  order = make_list("Version source", "Installed version", "Fixed version");
  report = make_array(
    order[0], source,
    order[1], version,
    order[2], "9.2.20 / 9.3.16 / 9.4.11 / 9.5.6 / 9.6.2"
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
