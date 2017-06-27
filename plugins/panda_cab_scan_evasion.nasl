#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38914);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/06/30 20:19:09 $");

  script_bugtraq_id(35072);
  script_osvdb_id(56048, 56049);

  script_name(english:"Panda Antivirus TAR / CAB Scan Evasion");
  script_summary(english:"Checks version of pskcmp.dll.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by a
scan evasion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Panda antivirus application installed on the remote host is
affected by a scan evasion vulnerability. An attacker can exploit this
by embedding malicious code in a specially crafted TAR or CAB file.");
  script_set_attribute(attribute:"see_also", value:"http://blog.zoller.lu/2009/04/advisory-panda-generic-evasion-tar.html");
   # http://www.pandasecurity.com/homeusers/support/card?id=80060&idIdioma=2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac47d1c" );
   # http://www.pandasecurity.com/homeusers/support/card?id=60039&idIdioma=2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c1b5ca8" );
   # http://www.pandasecurity.com/homeusers/support/card?id=70025&idIdioma=2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e381420" );
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory to apply the appropriate patch or update.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pandasecurity:panda_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright(C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "panda_antivirus_installed.nasl");
  script_require_keys("Antivirus/Panda/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

# Make sure Panda Antivirus is installed.
if (!get_kb_item("Antivirus/Panda/installed")) exit(0, "Panda Antivirus is not installed.");


# Connect to the appropriate share/
port     = kb_smb_transport();
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();

ver = NULL;

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

list = get_kb_list("Antivirus/Panda/*");
pat = "^([0-9\.]+) in (.+)";
foreach item (keys(list))
{
  matches = eregmatch(string:list[item], pattern:pat);
  if (!isnull(matches)) {
    path = matches[2];

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\pskcmp.dll", string:path);

    # nb. The hotfix updates pskcmp.dll from 1.5.1.0 to 1.5.1.13
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL,share);
    }

    fh = CreateFile(
      file:dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);

    if (!isnull(ver))
    {
      # Version of the dll after applying the hotfix = 1.5.1.13
      if (
        ver[0] < 1 ||
        (
          ver[0] == 1 &&
          (
            ver[1] < 5 ||
            (
              ver[2] < 1 ||
              (ver[2] == 1 && ver[3] < 13)
            )
          )
        )
      )
      {
        if (report_verbosity > 0)
        {
          version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
          report = string(
            "\n",
            path, "\\pskcmp.dll has not been patched.\n",
            "\n",
            "Remote version : ", version, "\n",
            "Should be      : 1.5.1.13\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port:port);

        if (!thorough_tests) break;
      }
    }
  }
}
NetUseDel();
