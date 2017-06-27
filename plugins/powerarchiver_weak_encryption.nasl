#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73380);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/07 20:29:25 $");

  script_cve_id("CVE-2014-2319");
  script_bugtraq_id(66174);
  script_osvdb_id(104421);

  script_name(english:"PowerArchiver 14.02.03 Incorrect PKZIP Encryption Usage");
  script_summary(english:"Checks file version of PowerArchiver");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
incorrect encryption usage vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has PowerArchiver version 14.02.03 installed. It is,
therefore, affected by a flaw with the encryption usage.

A flaw exists in the application where the insecure PKZIP encryption
method is used when a user attempts to encrypt files with AES 256-bit
encryption.

Note that Nessus has not attempted to exploit this issue, but has
instead relied only on the application's self-reported version number.");
  # http://www.powerarchiver.com/2014/03/12/powerarchiver-2013-14-02-05-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81bba388");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Mar/79");
  script_set_attribute(attribute:"solution", value:"Upgrade to PowerArchiver 14.02.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerarchiver:powerarchiver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("powerarchiver_detect.nbin");
  script_require_keys("SMB/PowerArchiver/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "PowerArchiver";
kb_base = "SMB/PowerArchiver/";

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "14.2.5.0";

# Only version 14.2.3.0 is vulnerable.
if (ver_compare(ver:version, fix:"14.2.3.0", strict:FALSE) != 0) audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
