#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17213);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/09/30 21:06:07 $");

 script_cve_id("CVE-2005-0533");
 script_bugtraq_id(12643);
 script_osvdb_id(14133);

 script_name(english:"Trend Micro VSAPI ARJ Handling Heap Overflow");
 script_summary(english:"Checks the version of the remote Trend Micro engine");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Trend Micro engine that has
a heap overflow vulnerability in the ARJ handling functions. 

An attacker may exploit this flaw to bypass virus protection altogether
and execute arbitrary code on the remote host.  To exploit this flaw, an
attacker would need to submit a malformed ARJ archive to a process on
the remote host and wait for the antivirus engine to scan it.");
 # http://about-threats.trendmicro.com/us/search.aspx?p=VULNERABILITY%20IN%20VSAPI%20ARJ%20PARSING%20COULD%20ALLOW%20REMOTE%20CODE%20EXECUTION
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2d903ac");
 script_set_attribute(attribute:"solution", value:"Upgrade to the Trend Micro engine version 7.510 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/24");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("trendmicro_installed.nasl");
 script_require_keys("Antivirus/TrendMicro/trendmicro_engine_version");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/TrendMicro/trendmicro_engine_version");
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 || 
  (ver[0] == 7 && ver[1] < 510)
)
{
  if (report_verbosity > 0)
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;

    report = '\n  Current engine version : ' + engine +
             '\n  Fixed engine version   : 7.510' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The remote host has engine version "+engine+" and thus is not affected.");
