#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33810);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2008-3449");
  script_bugtraq_id(30498);
  script_osvdb_id(47257);
  script_xref(name:"Secunia", value:"31325");

  script_name(english:"MailEnable IMAP Connection Saturation Remote DoS (ME-10042)");
  script_summary(english:"Checks version of MailEnable / Installed Hotfixes");

  script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a denial of service
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The IMAP server bundled with the version of MailEnable installed on
the remote host reportedly may crash under load when there are
multiple connections to the same folders." );
  script_set_attribute(attribute:"see_also", value:"http://www.mailenable.com/hotfix/" );
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix ME-10042." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mailenable_detect.nasl");
  script_require_keys("SMB/MailEnable/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("SMB/MailEnable/Installed")) exit(0);
if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";
else exit(0);


# Check for affected versions.
if (prod == "Professional" || prod == "Enterprise")
{
  kb_base = "SMB/MailEnable/" + prod;
  version = get_kb_item(kb_base+"/Version");
  hotfixes = get_kb_item(kb_base+"/Hotfixes");

  if (!isnull(version))
  {
    report = "";
    if (version =~ "^3\.52$" && (!hotfixes || "ME-10042" >!< toupper(hotfixes)))
    {
      report = string(
        "\n",
        "MailEnable ", prod, " Edition version ", version, " is installed on the\n",
        "remote host "
      );
      if (!hotfixes)
      {
        report = string(
          report, "without any hotfixes.\n"
        );
      }
      else
      {
        report = string(
          report, "with the following hotfixes :\n",
          "\n",
          "  ", hotfixes, "\n"
        );
      }
    }

    if (report)
    {
      if (report_verbosity) security_warning(port:get_kb_item("SMB/transport"), extra:report);
      else security_warning(get_kb_item("SMB/transport"));
    }
  }
}
