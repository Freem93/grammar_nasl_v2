#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52536);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/12 21:17:02 $");

  script_cve_id("CVE-2009-4269");
  script_bugtraq_id(42637);
  script_osvdb_id(67205);
  script_xref(name:"Secunia", value:"42948");

  script_name(english:"Apache Derby 'BUILTIN' Authentication Insecure Password Hashing");
  script_summary(english:"Checks the version of Apache Derby.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is running software known to be
susceptible to brute-forcing of passwords."
  );
  script_set_attribute(
    attribute:"description",
    value:

"According to its self-reported version number, the installation of
Apache Derby running on the remote server performs a transformation on
passwords that removes half the bits from most of the characters
before hashing.  This leads to a large number of hash collisions,
letting passwords be easily brute-forced.  This vulnerability only
affects the BUILTIN authentication method. 

Note that Nessus has not tested for the issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/jira/browse/DERBY-4483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://db.apache.org/derby/releases/release-10.6.1.0.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marcellmajor.com/derbyhash.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apache Derby 10.6.1.0 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("derby_network_server_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/derby", 1527);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"derby", exit_on_fail:TRUE);

version = get_kb_item_or_exit("derby/"+port+"/version");
fixed_version = '10.6.1.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'Apache Derby version '+version+' is installed on port '+port+' and hence not affected.');
