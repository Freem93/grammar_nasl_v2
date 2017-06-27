#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51920);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2011-0539");
  script_bugtraq_id(46155);
  script_osvdb_id(70873);
  script_xref(name:"Secunia", value:"43181");

  script_name(english:"OpenSSH Legacy Certificate Signing Information Disclosure");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:"Remote attackers may be able to access sensitive information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the banner, OpenSSH 5.6 or 5.7 is running on the remote
host. These versions contain an information disclosure vulnerability.
This vulnerability may cause the contents of the stack to be copied
into an SSH certificate, which is visible to a remote attacker. This
information may lead to further attacks."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 5.8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/legacy-cert.adv"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssh.com/txt/release-5.8"
  );
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);


# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");


# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];


if (version =~ "^5\.[67]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.8\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
} 
else exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
