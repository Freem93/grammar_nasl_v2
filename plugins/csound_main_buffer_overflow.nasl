#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58990);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 20:48:28 $");

  script_cve_id("CVE-2012-2107", "CVE-2012-2108");
  script_bugtraq_id(52876);
  script_osvdb_id(81015, 102848);

  script_name(english:"Csound util/lpci_main.c main() Function Multiple Buffer Overflows");
  script_summary(english:"Checks version of Csound install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Csound installed on the remote Windows host is less
than 5.17.2.  As such, it is reportedly affected by a stack- and a
heap-based buffer overflow present in the util/lpci_main.c main()
function. 

By tricking a user into opening a specially crafted file, an attacker
may be able to execute arbitrary code subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-6/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-4/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Csound version 5.17.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:csounds:csound");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("csound_getnum_buffer_overflow.nasl");
  script_require_keys("SMB/Csound/Installed");

  exit(0); 
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_kb_item("SMB/transport");
version = get_kb_item_or_exit("SMB/Csound/Version"); 
appname = "Csound";

path = get_kb_item("SMB/Csound/Path"); 

if (ver_compare(ver:version, fix:'5.17.2', strict:FALSE) == -1)
{
  if (report_verbosity > 0) 
  {
    report =  '\n  Path              : ' + path + 
              '\n  Installed version : ' + version + 
              '\n  Fixed version     : 5.17.2\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
