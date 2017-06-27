#TRUSTED 7cc98effe734050d045d4ec1fe56d536d309fe189752254d9451d70c76c2db620a963111807d2af1399eb6557458e71d085947bf8e073cadbb0ffed394d46b7c3e620658fe54a6de8b04323958cb04cb60419cce12f68224a778b2f659fefab29745eb1ea92946164acf2c5e679a9a099fe2001a5429a6741c1951b9ba326be136c15278609e681455187e358a5645049a70e38381170c83d80aaa520dbcff89ce545727f9edd3ddb93601b2e7cf8570e6058a83df2c3502482b260a44dacc3bcf8ef7e13ea36444c906e46920e16dff2d25dffad72bab39d762084789de9626abe3ee3b5399589e3f65cccf3da344de3c8b3db162b0aed3195adc58bb0fbcfa3ca7bf5fc97c5d382817f1716259b44b9084298ba2f7d379cb921e813a1c31e031b8ba29c8c2f741cc4c456fa2c637719232d8667287354f6c36590bb9cab69f3ecb1dded0db613fa98f639536834651a11ee9a09e2582010ba1a06f16903d17bcb16e4437cc4ec4c514cdcf4b7560892cc02ef2a483eab0b8d7bf54fa4c33bf482456ae0c970989d9e5e6e3766bdfe1759b199f4a59226dca6fe5ef3105981eaeed4c02095146a8d87adafd785d230b607f88d8eee455f86321678d89729004f7adaeb6f805e900d65c0a30c2de1ec1d344fdb73bcfffe33158bf0f6f89a2eb29d2bead6b4bd886cf052d07987cc23b2dc8a2065a67defee21ad6192776856f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72261);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/02");

  script_cve_id("CVE-2013-4128", "CVE-2013-4213");
  script_bugtraq_id(61739, 61742);
  script_osvdb_id(96216, 96217);
  script_xref(name:"RHSA", value:"2013:1152");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1152)");
  script_summary(english:"Checks for the install versions of JBoss Enterprise Application Platform");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is vulnerable to the following issues:

  - A flaw in the way authenticated connections are cached
    on the server by remote-naming could allow a remote
    attacker to log in as another user without knowing
    their password. (CVE-2013-4128)

  - A flaw in the way connections for remote EJB
    invocations via the EJB client API are cached on the
    server could allow a remote attacker to use an EJB
    client to log in as another user without knowing their
    password. (CVE-2013-4213)");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4128.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4213.html");

  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");

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
jboss = 0;
installs = get_kb_list_or_exit("Host/JBoss/EAP");
if(!isnull(installs)) jboss = 1;

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
      found = 0;
      cmd = 'test -f "' + path + 'modules/system/layers/base/org/jboss/remote-naming/main/jboss-remote-naming-1.0.6.Final-redhat-2.jar" && echo FOUND';
      buf = info_send_cmd(cmd:cmd);
      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      cmd = 'test -f "' + path + 'modules/system/layers/base/org/jboss/ejb-client/main/jboss-ejb-client-1.0.21.Final-redhat-1.jar" && echo FOUND';
      buf = info_send_cmd(cmd:cmd);
      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      if (found)
      {
        info += '\n' + '  Path    : ' + path+ '\n';
        info += '  Version : ' + ver + '\n';
      }
    }
  }
}

# Report what we found.
if (info)
{
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
