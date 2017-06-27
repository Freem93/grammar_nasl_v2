#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56385);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/12/03 23:29:26 $");
 
  script_cve_id(
    "CVE-2011-0333",
    "CVE-2011-0334",
    "CVE-2011-2218",
    "CVE-2011-2219",
    "CVE-2011-2662",
    "CVE-2011-2663"
  );
  script_bugtraq_id(49774, 49775, 49777, 49779, 49781);
  script_osvdb_id(75769, 75770, 75771, 75772, 75774, 75775);

  script_name(english:"GroupWise Internet Agent < 8.0.2 HP3 Multiple Vulnerabilities");
  script_summary(english:"Checks GWIA version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Internet Agent running on the remote
host is earlier than 8.0.2 HP3.  Such versions are potentially
affected by multiple issues :

  - Multiple denial of service issues exist because the
    application does not adequately verify user-supplied 
    inputs. (CVE-2011-2218, CVE-2011-2219)

  - A stack-based buffer overflow exists because the 
    application fails to perform adequate boundary checks on
    user-supplied data. (CVE-2011-0334)

  - A remote code execution vulnerability exists in the 
    GroupWise Internet Agent Yearly RRULE variable.
    (CVE-2011-2663)
    
  - A remote code execution vulnerability exists due to the
    way the application parses the time zone description 
    (TZNAME) variable within a received VCALENDAR message.
    (CVE-2011-0333)
    
  - A remote code execution vulnerability exists due to the
    way the application parses the weekly calendar 
    recurrence (RRULE) variable within a received VCALENDAR
    message. (CVE-2011-2662)");

   # http://www.novell.com/support/kb/doc.php?id=7006378
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c0a7f23");
   # http://www.novell.com/support/kb/doc.php?id=7009210
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb2ae5ca");
   # http://www.novell.com/support/kb/doc.php?id=7009216
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96f7e22e");
   # http://www.novell.com/support/kb/doc.php?id=7009208
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f078d7e");
   # http://www.novell.com/support/kb/doc.php?id=7009215
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2967b20");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-66/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-67/");
  script_set_attribute(attribute:"solution", value:
"Update GWIA to version 8.0.2 Hot Patch 3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "groupwise_ia_detect.nasl");
  script_require_keys("SMB/GWIA/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

# Unless we're paranoid, make sure the service is running.
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit("SMB/svc/GWIA");
  if (status != SERVICE_ACTIVE)
    exit(0, "The GroupWise Internet Agent service is installed but not active.");
}

# Check the version number.
version = get_kb_item_or_exit("SMB/GWIA/Version");
fixed_version = '8.0.2.16933';
if (ver_compare(ver:version, fix:fixed_version) == -1) 
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/GWIA/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "GroupWise Internet Agent version "+ version + " is installed and hence is not affected.");
