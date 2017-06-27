#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42354);
 script_version ("$Revision: 1.5 $");

 script_bugtraq_id(36886);

 script_name(english: "Intel Desktop Board Bitmap Processing Buffer Overflow (INTEL-SA-00020)");
 script_summary(english: "Check Intel BIOS version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:
"The remote host is affected by a local buffer overflow
vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:
"The version of the Intel BIOS on the remote host is affected by a
local buffer overflow vulnerability due to a flaw in its Bitmap
processing code.  A local attacker may be able to leverage this issue
to trigger a denial of service or to escalate privileges."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?3573e61d"
 );
 script_set_attribute(
   attribute:"solution", 
   value:
"Upgrade to the relevant BIOS firmware referenced in the vendor's
advisory."
 );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/30"
 );
 script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/30"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/03"
  );
 script_cvs_date("$Date: 2011/03/21 01:56:46 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor", "BIOS/ReleaseDate");
 exit(0);
}

include("global_settings.inc");

vendor = get_kb_item("BIOS/Vendor");
if (isnull(vendor)) exit(1, "No BIOS vendor found in the KB.");
if (vendor !~ "^Intel ")  exit(0,"The BIOS vendor is not Intel.");

version = get_kb_item("BIOS/Version");
if (isnull(version)) exit(0, "NO BIOS version found in the KB.");

updates = make_list(
  "CBQ4510H.86A.0101.2009.0928.1248",
  "JOQ3510J.86A.1122.2009.1027.2020"
);

v = split(version, sep: '.', keep: 0);
if (max_index(v) < 6)  exit(1,"max_index (v) < 6");

foreach u (updates)
{
 w = split(u, sep: '.', keep: 0);
 if (v[0] == w[0])
 {
   if (int(v[2]) < int(w[2]) ||
         v[2] == w[2] && ( int(v[3]) < int(w[3]) ||
           v[3] == w[3] && ( int(v[4]) < int(w[4]) ||
       	      v[4] == w[4] && int(v[5]) < int(w[5]))))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "  Current firmware version    : ", version, "\n",
          "  Upgrade to firmware version : ", u, "\n"
        );
        security_warning(port:0, extra:report);
      }
      else security_warning(0);
      exit(0);
    }  
  }
}
exit(0, "Installed Intel BIOS version '" + version + "' is not affected.");
