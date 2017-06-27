#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38866);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");
  script_bugtraq_id("35067");
  script_osvdb_id(54646, 54647, 54648, 54649);

  script_name(english:"Pidgin < 2.5.6 Multiple Buffer Overflows");
  script_summary(english:"Checks the version number of Pidgin");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an instant messaging client that is
affected by multiple buffer overflow vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Pidgin earlier than 2.5.6. Such versions
are reportedly affected by multiple buffer overflow vulnerabilities :

  - A buffer overflow is possible when initiating a file
    transfer to a malicious buddy over XMPP. (CVE-2009-1373)

  - A buffer overflow issue in the 'decrypt_out()' function 
    can be exploited through specially crafted 'QQ' packets.
    (CVE-2009-1374)

  - A buffer maintained by PurpleCircBuffer which is used by
    XMPP and Sametime protocol plugins can be corrupted if
    it's exactly full and then more bytes are added to it.
    (CVE-2009-1375)

  - An integer-overflow issue exists in the application due
    to an incorrect typecasting of 'int64' to 'size_t'.
    (CVE-2009-1376)" );
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=29" );
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=30" );
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=31" );
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=32" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pidgin 2.5.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/22");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("global_settings.inc");

version = get_kb_item("SMB/Pidgin/Version");
if (version)
{
  ver = split(version, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 2 ||
    (
      int(ver[0]) == 2 &&
      (
        int(ver[1]) < 5 ||
        (int(ver[1])==5 && int(ver[2]) < 6)
      )
    )
  )
  {
    if(report_verbosity>0)
    {
      report = string(
        "\n",
        "Nessus found the following version of Pidgin installed :\n",
        "\n",
        "  ", version, "\n"
      );
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(port:get_kb_item("SMB/transport"));
  }
}
