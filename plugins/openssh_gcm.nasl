#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70895);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2013-4548");
  script_bugtraq_id(63605);
  script_osvdb_id(99551);

  script_name(english:"OpenSSH 6.2 and 6.3 AES-GCM Cipher Memory Corruption");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server on the remote host is affected by a memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is version 6.2 or 6.3.  It is, therefore, affected by a memory
corruption vulnerability in post-authentication when the AES-GCM cipher
is used for the key exchange.  Exploitation of this vulnerability could
lead to arbitrary code execution. 

Note that installations are only vulnerable if built against an OpenSSL
library that supports AES-GCM."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/gcmrekey.adv");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 6.4 or refer to the vendor for a patch or
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_dependencies("ssh_detect.nasl", "ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) audit(AUDIT_BACKPORT_SERVICE, 22, "OpenSSH");

match = eregmatch(string:tolower(bp_banner), pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

if (version =~ "^6\.[23]($|[^0-9])")
{
  if (report_paranoia < 2)
  {
    types = make_list("client_to_server", "server_to_client");
    fail = 0;
    vuln = 0;
    foreach type (types)
    {
      algs = get_kb_list("SSH/" + port + "/encryption_algorithms_" + type);
      if (isnull(algs)) fail++;
      else
      {
        algs = make_list(algs);
        foreach alg (algs)
          if ('aes128-gcm' >< alg || 'aes256-gcm' >< alg) vuln++;
      }
    }
    if (fail > 1)
      exit(1, "Failed to retrieve list of supported encryption algorithms on remote host.");
    if (!vuln)
      exit(0, "OpenSSH installed on the remote host is not affected because AES-GCM is not supported.");
  }
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.4' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
