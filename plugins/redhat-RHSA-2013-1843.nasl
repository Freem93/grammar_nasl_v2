#TRUSTED 596ffb6b5f18b2c07f94464e6978c7339f8d73863cb94d3be5f42c4a938684a61d41eaf16ad30088e3e18e942c718458824fe2ea5d0be62dca2e113dce63aeaba8b70c5e506aab7e9ab62bb97e2d6a9cec6b1d7ccdfc6a65136453a324fbeda0b614067317152d728af0d6fb869ba3fa0470f084777b0d3e163514f54e4b6c530315723a7e2431cac7a4f1feb29a90f20abe56210afda7ec74259cab9a2a4f192adc70371899028b948e5f2f3d40bfa860f6091dbe53078cdac494130246eb3565b39b6a0ab4106a0910299d0c168a35e858d67cf0daaa53bed4696fd7411703141a101d956de8b2823a3c488cd6dd533c1398087d5127a43b8c73d9e30dda85fbbc4e2a464eb97779a0c7725dd18a8c51b8a0070e4a53751b8d630c1c0159b78513edb292f6bbb5971e555b5a979963d842a268692e02b0580ed8f8ab1bc8340746c7e8c68b5996aba82e0f3b81bac7edab2c892c228eae17a6f85eba797b10179113009b4d212c81a3850bd4714e76cd2fb5df507fccab53a4a5c5160f87c515da7a8f712d5ca9291e2d6753678fc0b9b52607eb8d2230bc1f47110ab16d204e63f7e13d107c0fee43bfcf4b101266eed9439f284f357622b680e60e627f981b52df3b5606fb6f51e16aa482a4111e9566a17c18f33778154dafd9bb7cd8e03341d7911ea08026fb3fddcadeadf5ffedb9b5fa9da27f9bc93837b5d91e6bbd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72390);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/02");

  script_cve_id("CVE-2013-4424");
  script_bugtraq_id(64365);
  script_osvdb_id(101067);
  script_xref(name:"RHSA", value:"2013:1843");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1843)");
  script_summary(english:"Checks for the install versions of JBoss Enterprise Application Platform");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is affected by multiple cross-site scripting flaws in
the GateIn Portal component. This could allow a remote attacker to
manipulate a logged in user into visiting a specially crafted URL,
thereby executing an arbitrary web script in the context of the user's
GateIn Portal session.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4424.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/JBoss/EAP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("datetime.inc");

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");

installs = get_kb_list_or_exit("Host/JBoss/EAP");

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

info = "";
jboss = TRUE;

foreach install (make_list(installs))
{
  match = eregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(match))
  {
    ver = match[1];
    path = match[2];

    # check for install version = 6.1.0
    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      # check that the target file exists
      cmd = 'test -f "' + path + 'modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar" && echo FOUND';
      buf = info_send_cmd(cmd:cmd);
      if ( (buf) && ("FOUND" >< buf) )
      {
        # extract the needed line from the file
        cmd = 'unzip -p ' + path + 'modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar META-INF/MANIFEST.MF | grep "Build-Timestamp"';
        buf = info_send_cmd(cmd:cmd);
        if ( (buf) )
        {
          # parse the line into the needed date portions
          match = eregmatch(string:buf, pattern:"Build-Timestamp: [^,]+,\s+(\d+)\s+([A-Za-z]+)\s+(\d+)");

          if (!isnull(match))
          {
            day = match[1];
            month = month_num_by_name(match[2], base:1);
            year = match[3];

            # compare the dates to see if it is older than the patch
            if (ver_compare(ver:year+"."+month+"."+day, fix:"2013.11.27") < 0)
            {
              info += '\n' + '  Path    : ' + path+ '\n';
              info += '  Version : ' + ver + '\n';
            }
          }
        }
      }
    }
  }
}

# Report what we found.
if (info)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
    else s = ' of JBoss Enterprise Application Platform is';

    report =
      '\n' +
      'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
      info;

    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else if ( (!info) && (jboss) )
{
  exit(0, "The JBoss Enterprise Application Platform version installed is not affected.");
}
else audit(AUDIT_HOST_NOT, "affected");
