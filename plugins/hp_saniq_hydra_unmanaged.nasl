#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73462);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2014/04/11 00:58:06 $");

  script_name(english:"HP LeftHand OS Unmanaged Host Detection");
  script_summary(english:"Detects unmanaged LeftHand OS Hosts");

  script_set_attribute(attribute:"synopsis", value:"The remote storage system is currently unmanaged.");
  script_set_attribute(attribute:"description", value:
"The remote HP storage system running HP LeftHand OS (formerly known as
SAN/iQ) is in an unmanaged state, meaning that it can be accessed and
controlled by any remote user and is not protected by any credentials.");
  script_set_attribute(attribute:"see_also", value:"http://h10032.www1.hp.com/ctg/Manual/c01750064.pdf");
  # https://h20392.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=StoreVirtualSW
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?8ab2c364");
  script_set_attribute(attribute:"solution", value:
"Add the device to a management group using the centralized management
console.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:lefthand");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("hp_saniq_hydra_detect.nbin", "hp_lefthand_console_discovery.nasl");
  script_require_ports("Services/hydra_saniq", 13838);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("hp_saniq_hydra.inc");

global_var soc, port;

function test_login(version)
{
  local_var login_res;

  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  login_res =
  hp_hydra_login(socket:soc,
                 port:port,
                 username:rand_str(),
                 password:rand_str(),
                 version:version,
                 exit_on_fail:TRUE);
  close(soc);
  if (login_res == HP_HYDRA_LOGIN_OK) return TRUE;
  else return FALSE;
}

port = get_service(svc:"hydra_saniq", default:13838, exit_on_fail:TRUE);

version_list = NULL;

kb_list = get_kb_list('lefthand_os/*/version');
if (!isnull(kb_list))
{
  version_list = make_list();
  foreach version (kb_list)
  {
    ver = split(version, sep:'.', keep:FALSE);
    version_list = make_list(version_list, ver[0] + '.' + ver[1]);
  }
  version_list = list_uniq(version_list);
}

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

vuln = FALSE;

login_ver = '';

# try logins using detected versions first
if (!isnull(version_list))
{
  foreach version (version_list)
  {
    if (test_login(version:version))
    {
      login_ver = version;
      vuln = TRUE;
      break;
    }
  }
}

# try more comprehensive version list
if (!vuln)
{
  if (isnull(version_list))
  {
   # the first "100.0" version should work against all current versions
   # It doesn't exist, but it's high enough that it would *theoretically* be backwards
   # compatible with all known version
    version_list = make_list(
      "100.0", "8.0", "8.1", "8.5", "9.0", "9.5", "10.5", "11.0"
    );
  }

  foreach version (version_list)
  {
    if (test_login(version:version))
    {
      login_ver = version;
      vuln = TRUE;
      break;
    }
  }
}

# if device is vulnerable, the code below will try and run an interesting command
# and add it to the report
if (vuln)
{
  if (report_verbosity > 0)
  {
    soc = open_sock_tcp(port);
    if (!soc) audit(AUDIT_SOCK_FAIL, port);

    res = '';

    login_res =
    hp_hydra_login(socket:soc,
                   port:port,
                   username:rand_str(),
                   password:rand_str(),
                   version:login_ver,
                   exit_on_fail:TRUE);

    if (login_res == HP_HYDRA_LOGIN_OK)
    {
      res = hp_hydra_run_command(socket:soc,
                                 port:port,
                                 cmd:'get:/lhn/public/system/info/report/diskSetup/',
                                 exit_on_fail:TRUE);
    }

    close(soc);

    if ('OK:<Report Type="DiskSetup">' >< res)
    {
      report = '\nNessus was able to demonstrate the issue by running the following protected' +
               '\ncommand on the remote device :\n' +
               '\n  "get:/lhn/public/system/info/report/diskSetup/"\n';

      if (
          !defined_func("nasl_level") ||
          nasl_level() < 5200 ||
          !isnull(get_preference("sc_version"))
      )
      {
        report += '\n' + 'Command response :' +
                  '\n' +
                  '\n' + chomp(res) + '\n';

        security_hole(port:port, extra:report);
      }
      else
      {
        report += '\n' + 'Attached is the command response.\n';

        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = 'disk_setup.txt';
        attachments[0]["value"] = chomp(res);

        security_report_with_attachments(level:3, port:port, extra:report, attachments:attachments);
      }
    }
    else security_hole(port);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "HP LeftHand OS", port);
