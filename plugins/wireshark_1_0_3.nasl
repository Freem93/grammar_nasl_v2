#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34113);
  script_version("$Revision: 1.10 $");

  script_bugtraq_id(31009);

  script_name(english:"Wireshark / Ethereal < 1.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks Wireshark / Ethereal version"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by multiple
issues :

  - The NCP dissector is affected by multiple buffer
    overflow flaws, and in certain cases may enter a 
    infinite loop (Bug 2675).

  - While uncompressing zlib-compressed packet data, 
    Wireshark could crash (Bug 2649).

  - While reading a Tektronix .rf5 file, Wireshark could 
    crash." );
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark 1.0.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/09");
 script_cvs_date("$Date: 2016/05/06 17:22:03 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");

# Check Wireshark/Ethereal installs
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0);

info = "";
info2 = "";
foreach install (keys(installs))
{
  if ("/Installed" >< install) continue;

  ver = install - "SMB/Wireshark/";
  if (ver)
   {
    v = split(ver, sep:".", keep:FALSE);
    for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

    if (
      (
        v[0] == 0 && 
        (
          (v[1] == 9 && v[2] >= 7) ||
          v[1] > 9
        )
      ) ||
      (v[0] == 1 && v[1] == 0 && v[2] < 3)
    ) 
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.0.3\n';
    else
      info2 += '  - Version ' + ver + ', under ' + installs[install] + '\n';
   }
}

if(info)
{
  if (report_verbosity)
   {
    if (max_index(split(info)) > 4) s = "s of Wireshark or Ethereal are";
    else s = " of Wireshark or Ethereal is";

    report = string(
          "\n",
          "The following vulnerable instance",s," installed \n",
	  "on the remote host :\n",
	  "\n",
	  info
        );
     security_note(port:port, extra:report);
   }
   else
     security_note(port);
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
