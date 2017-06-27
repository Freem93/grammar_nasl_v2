#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54583);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_cve_id("CVE-2011-1720");
  script_bugtraq_id(47778);
  script_osvdb_id(72259);
  script_xref(name:"CERT", value:"727230");
  script_xref(name:"Secunia", value:"44500");

  script_name(english:"Postfix Cyrus SASL Authentication Context Data Reuse Memory Corruption");
  script_summary(english:"Checks version of SMTP banner and SASL auth modes");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote mail server is potentially affected by a memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its banner, the version of the Postfix mail server
listening on this port is earlier than 2.5.13, 2.6.19, 2.7.4, or
2.8.3.  Such versions may be vulnerable to a memory corruption attack
if they have Cyrus SASL enabled and are allowing authentication
methods other than ANONYMOUS, LOGIN, and PLAIN.  Code execution as the
unprivileged postfix user may also be possible. 

Note that Nessus did not test whether the remote server was using
Cyrus specifically, as opposed to another SASL library such as
Dovecot."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postfix.org/CVE-2011-1720.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2011/May/64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Postfix 2.5.13 / 2.6.19 / 2.7.4 / 2.8.3 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("smtp_authentication.nasl");
  script_require_ports("Services/smtp", 25);
  script_require_keys("Settings/ParanoidReport", "SMTP/postfix");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

# Get the service's banner.
banner = chomp(get_smtp_banner(port:port));
if (isnull(banner))
  exit(1, "Failed to retrieve the banner from the SMTP server listening on port " + port + ".");
if ("Postfix" >!< banner)
  exit(0, "The banner from the SMTP server listening on port " + port + " is not from Postfix.");

# Get authentication methods.
methods = make_list();
list = get_kb_list("smtp/" + port + "/auth");
if (!isnull(list))
  methods = make_list(methods, list);
list = get_kb_list("smtp/" + port + "/auth_tls");
if (!isnull(list))
  methods = make_list(methods, list);
if (!max_index(methods))
  exit(0, "Postfix on port " + port + " doesn't support authentication.");

# Only three methods are unaffected, per the advisory.
affected = FALSE;
auth_methods = '';
foreach method (methods)
{
  auth_methods += ', ' + method;
  if (method != "ANONYMOUS" && method != "LOGIN" && method != "PLAIN")
  {
    affected = TRUE;
    break;
  }
}
if (!affected)
  exit(0, "Postfix on port " + port + " does not have any of the affected SASL methods enabled.");
auth_methods = substr(auth_methods, 2);

# Parse the version number from the banner.
#
# nb: the pattern here extracts the version in two parts potentially -
#     one that's entirely numeric and suitable for use in 'ver_compare()',
#     a second that may have non-numeric parts but is not used in the version checks.
matches = eregmatch(pattern:"220.*Postfix \(([0-9\.]+)(-(RC)?[0-9]+)?\)", string:banner);
if (isnull(matches))
  exit(1, "Failed to determine the version of Postfix based on the banner from the SMTP server listening on port " + port + ".");
version = matches[1];

# Check if the version is vulnerable.
if (version =~ "^([0-1]\.|2\.[0-5]($|[^0-9]))")
{
  fixed = "2.5.13";
  vuln = ver_compare(ver:version, fix:fixed, strict:FALSE);
}
else if (version =~ "^2\.6")
{
  fixed = "2.6.19";
  vuln = ver_compare(ver:version, fix:fixed, strict:FALSE);
}
else if (version =~ "^2\.7")
{
  fixed = "2.7.4";
  vuln = ver_compare(ver:version, fix:fixed, strict:FALSE);
}
else if (version =~ "^2\.8")
{
  fixed = "2.8.3";
  vuln = ver_compare(ver:version, fix:fixed, strict:FALSE);
}
else
{
  # Any later versions will include the fix for this issue.
  vuln = 1;
}

if (vuln >= 0)
  exit(0, "Postfix version " + version + " is running on the port " + port + " and not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Banner                      : ' + banner +
    '\n  Installed version           : ' + version +
    '\n  Fixed version               : ' + fixed +
    '\n  Supported SASL auth methods : ' + auth_methods +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
