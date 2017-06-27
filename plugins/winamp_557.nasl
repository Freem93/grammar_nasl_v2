#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(43181);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2009-3995", "CVE-2009-3996", "CVE-2009-3997", "CVE-2009-4356");
  script_bugtraq_id(37374, 37387);
  script_osvdb_id(61184, 61185, 62138, 62139);
  script_xref(name:"Secunia", value:"37495");
  
  script_name(english:"Winamp < 5.57 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Winamp.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.57.  Such versions are potentially affected by multiple issues :

  - A boundary error in the Module Decoder Plug-in exists 
    when parsing samples and can be exploited to cause a 
    heap-based buffer overflow. (CVE-2009-3995)

  - An error in the Module Decoder Plug-in when parsing
    'Ultratracker' fields and can be exploited to cause a
    heap-based buffer overflow. (CVE-2009-3996)

  - An integer overflow error in the Module Decoder Plug-in
    when parsing 'Oktalyzer' files and can be exploited to
    cause a heap-based buffer overflow. (CVE-2009-3997)
    
  - Integer overflow errors within the 'jpeg.w5s' and
    'png.w5s' filters when processing malformed 'JPEG' or
    'PNG' data in a media file. (CVE-2009-4356)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e4f075b"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2009-53/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2009-56/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2009-57/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/508532/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Winamp version 5.57 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/17");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
# Check version of Winamp.

#
# nb : the KB item is based on GetFileVersion, which may differ
#      from what the client reports.

version = get_kb_item("SMB/Winamp/Version");
if (isnull(version)) exit(1, "The 'SMB/Winamp/Version' KB item is missing.");
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("5.5.7.2789", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity > 0)
    {
      path = get_kb_item("SMB/Winamp/Path");
      report = 
        '\n'+
        'Product                : Winamp\n' +
        'Path                   : ' + path + '\n'+
        'Installed file version : ' + version + '\n'+
        'Fixed file version     : 5.5.7.2789\n';
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
  else if (ver[i] > fix[i])
    break;
exit(0, 'The host is not affected because winamp.exe version '+version+' was found.');
