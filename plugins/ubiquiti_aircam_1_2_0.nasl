#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72580);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/19 16:36:01 $");

  script_cve_id("CVE-2013-1606");
  script_bugtraq_id(60487);
  script_osvdb_id(94211);
  script_xref(name:"EDB-ID", value:"26138");

  script_name(english:"Ubiquiti airCam < 1.2.0 ubnt-streamer RTSP Service Remote Code Execution");
  script_summary(english:"Checks the Ubiquiti airCam firmware version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the firmware installed
on the remote host is prior to 1.2.0.  It is, therefore, affected by a
remote code execution vulnerability in the 'ubnt-streamer' RTSP service
when parsing an overly large URI of a RTSP request message.  An attacker
can exploit this issue to cause a denial of service or execute arbitrary
code.");
  # http://www.coresecurity.com/advisories/buffer-overflow-ubiquiti-aircam-rtsp-service
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b16afeb2");
  # http://community.ubnt.com/t5/airVision-Blog/airVision-2-1-1-airCam-1-2-fw-Released/ba-p/486207
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b598e5bd");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ubnt:airvision_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ubiquiti_aircam_detect.nbin");
  script_require_keys("Ubiquiti/airCam/Device", "Ubiquiti/airCam/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "Ubiquiti/airCam";

version = get_kb_item_or_exit(kb_base+"/Version");

fixed = '1.2.0';
if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since firmware version " + version + " is installed.");

