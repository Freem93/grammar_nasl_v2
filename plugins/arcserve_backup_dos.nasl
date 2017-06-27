#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58607);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2012-1662");
  script_bugtraq_id(52655);
  script_osvdb_id(80212);

  script_name(english:"CA ARCserve Backup Network Service Network Request Parsing Remote DoS");
  script_summary(english:"Checks version of CA ARCserve Backup");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service is affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of CA ARCserve Backup on
the remote host allows a remote attacker to cause a denial of service
condition via a specially crafted network request. 

Note that this plugin cannot detect if the patch correcting this issue
for r12.0 or r15 SP1 (build 6300) has been applied."
  );
  #https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={983E3A52-8374-410A-82BD-B8788733C70F}
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aea9f62d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Mar/237");
  script_set_attribute(
    attribute:"solution",
    value:
"Either apply the appropriate patch as described in the vendor advisory
referenced above, or upgrade to CA ARCserve Backup r12.5 SP2 / r16 SP1
or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "arcserve_discovery_service_detect.nasl");
  script_require_keys("ARCSERVE/Discovery/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) exit(0, "Only Windows hosts are reported to be affected.");
}

ver_ui = get_kb_item_or_exit("ARCSERVE/Discovery/Version");
port = get_kb_item_or_exit("Services/udp/casdscsvc");

matches = eregmatch(string:ver_ui, pattern:"^[a-z]([0-9]+\.[0-9]+) \(build ([0-9]+)\)$");
if (isnull(matches)) exit(1, "Failed to parse the version ("+ver_ui+") of the discovery service listening on port "+port+".");

ver = matches[1];
build = int(matches[2]);

if (report_paranoia < 2)
{
  if (ver == "15.1") exit(1, "The version r15 SP1 install on port "+port+" may be already be patched.");
  if (ver == "12.0") exit(1, "The version r12.0 install on port "+port+" may be already be patched.");
}
 
if (ver == "16.0" && build < 6838)      fix = "r16.0 SP1 (build 6838)";
else if (ver == "12.5" && build < 5900) fix = "r12.5 SP2 (build 5900)";
else if (ver == "12.0")                 fix = "r16 SP1 or patch T146564";
else if (ver == "15.0")                 fix = "r15 SP1 and patch R042050";
else if (ver == "15.1")                 fix = "patch R042050";
else exit(0, "The CA ARCserve Backup Discovery service version "+ver_ui+" install on port " + port + " is not affected.");

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + ver_ui +
           '\n  Fixed version     : ' + fix + 
           '\n'; 
  security_warning(port:port, proto:"udp", extra:report);
} 
else security_warning(port:port, proto:"udp");
