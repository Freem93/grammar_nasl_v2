#TRUSTED 97b743a3df39d352f3e6c207d0138bea7883db7b65efae31f0d2be8420e64ff3cd34feda47ff095c26d92d0345c2ec39d964beef7656e15349a97debca61bbde5bf83a74f792ecfbaf243ed7be071b3516e27e420ccbedad202d284bcc540480b01053edb888e0561f6ad73d0cb50c7123420519d87c1270917d59870c436bd9c630cb72be4edac1051fb5023f7a4d49d71352deae00fccd49d2bfaeabe24575e10d98db0a2e4310838cabeb796e30979e8eba94cf572a2b4934e7c8fb7bd1c3ef981262a597c1b22efb7be4d610c348e50d7ef9e1be15d187eafae824a544a449649e15a5bfebe1094fd8d163bbec61dc0a13e98ea499d6dbc6ec0b95a1646c7714bba79e603e4ec374ec71b98db5dbf9b03633976bbb987357e30e7f64587068c2d0a12e89bc160757f05f4fb18f5f1584626bc5e504f29ea113f63cfa6304c61b61cdf6b19b61084c083b425d048f6eb4958e20a6fdc04cd5f46cdec969d52abfd70dae5fc7f3b3a8382170c516223cfb773af180083fad3a45ec4b61f8a8895f6bd8f2c4a3a0ee28a392b6946461f6a773d6bd9e3ccf1ed83f8fa293cbcf2a84ffcf062dfd5b76001b1a13bf9db57aab7f94874fdf9f3e73b7dec9a61613966f5af60fc75c4fc9495c56cd6c13c01ffc0588b4d34473d776422ab31cd478aa7ee0f67f7cb06e9a681eba55d7e47bbe490ecc84ec2220015d9030df659e1c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64815);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/07");

  script_name(english:"Oracle Java Runtime Environment (JRE) Detection (Unix)");
  script_summary(english:"Checks for Oracle/Sun JRE installs.");

  script_set_attribute(attribute:"synopsis", value:
"The Java runtime environment is installed on the remote Unix host.");
  script_set_attribute(attribute:"description", value:
"One or more instances of Oracle's (formerly Sun's) Java Runtime
Environment (JRE) are installed on the remote host. This may include
private JREs bundled with the Java Development Kit (JDK).

Note that this plugin does not detect non-Oracle JRE instances such
as OpenJDK, GCJ, IBM Java, etc.");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "oracle_enum_products_nix.nbin");
  script_require_keys("Host/local_checks_enabled");
  script_timeout(640); # Allow find a bit more time than the default

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("install_func.inc");
include("find_cmd.inc");

##
# Checks to see if a java install is bundled with an Oracle Product
#
# @remark This function basically checks to see if javapath contains any known
#         ohome path.
#
# @param javapath string absolute path to the java binary to check
#
# @returns TRUE if javapath is bundled in an Oracle application, FALSE if not
##
function oracle_bundled_java(javapath)
{
  # Optimization: if no Oracle products are installed it can't be bundled
  if(!get_kb_item("Oracle/Products/Installed"))
    return FALSE;
  local_var sqlq = "SELECT path FROM oracle_homes";
  local_var sqlr = query_scratchpad(sqlq);
  local_var row  = NULL;
  if(isnull(sqlr))
    return FALSE;
  foreach row (sqlr)
  {
    if(row["path"] >< javapath)
      return TRUE;
  }
  return FALSE;
}

# Simple wrapper to make run_cmd_template a drop in replacement for
# info_send_cmd
function run_cmd_template_wrapper(template,args)
{
  local_var resp;
  resp = run_cmd_template(template:template,args:args);
  if (resp['error'] == HLF_OK)
    resp = resp['data'];
  else
    resp = NULL;
  return resp;
}

# Attempts to resolve a symlinks "true" path via namei if
# namei is not available we will use ls and follow up to
# 5 links, if item is not a symlink or cannot be resolved
# in 5 traversals it is returned unchanged otherwise 
# the true path is returned.
function resolve_symlink(item)
{
  local_var sympath,buf2,line,lines,count,path;

  # If the path / item doesn't start with / 
  # then its an error like "find : cycle detect"
  # ect ...
  if(item !~ "^/(.*)$")
    return item;

  sympath = '';
  buf2 = info_send_cmd(cmd:"namei " + item);
  if (buf2 && 'not found' >!< buf2 && "segmentation fault" >!< tolower(buf2))
  {
    lines = split(buf2, keep:FALSE);
    foreach line (lines)
    {
      # symlinks start with 'l'
      if (ereg(pattern:'^(\\s)+l .*', string:line))
        sympath = ereg_replace(pattern:'^(\\s)+l [^>]+> (.*)$', string:line, replace:"\2");
    }
    if (sympath) item = chomp(sympath);
  }
  # Not all hosts support namei. In those cases,
  # just use ls to follow the symlink
  else
  {
    # Go up to 5 deep on the symlinks
    count = 0;
    while (count < 5)
    {
      path = item;
      path = ereg_replace(pattern:"^(.*)/$",string:path,replace:"\1"); # Strip trailing /
      buf2 = info_send_cmd(cmd:"ls -l " + path);
      # No buf : there was an error return original item
      if (!buf2)
        break;
      #  Not a symlink : we're done following
      if (buf2 !~ "^l.*")
        break;

      sympath = ereg_replace(pattern:'^l[^>]+> (.*)', string:buf2, replace:"\1");
      # Some more mangling in case the symlink points to ../*
      # so we can get the correct path
      # For each ../ remove one level from the path until ../ is no longer
      # in the symlink path or we are at the root directory for path
      if (sympath =~ '^../')
      {
        while (sympath =~ '^../')
        {
          path = ereg_replace(pattern:'^(/.*/).*/.*', string:path, replace:"\1");
          if (path == '/')
          {
            sympath = sympath - '../';
            path = path + sympath;
            break;
          }
          sympath = substr(sympath, 3);
        }
        path = path + sympath;
        item = chomp(path);
      }
      # Absolute sympath
      else if(sympath =~ "^/(.*)$")
      {
        item = chomp(sympath);
      }
      # Symlink relative to it's parent dir
      else
      {
        path = ereg_replace(pattern:'^(.*)/[^/]+$',string:path, replace:"\1");
        item = chomp(path)+"/"+chomp(sympath);
      }
      count++;
    }
  }
  return item;
}

function java_version(java,shell_path)
{
  local_var buf2,temp_buf,v,ver,ver_formatted;

  if(isnull(shell_path))
    shell_path = "/bin/bash";

  buf2 = info_send_cmd(cmd:shell_path+" -c '"+java + " -version 2>&1'");
  # In some cases, the java binary is stripped out of item by namei
  # If that happened, try sending the command again with /bin/java appended
  if (!isnull(buf2) && 'is a directory' >< tolower(buf2))
  {
    java += '/bin/java';
    buf2 = info_send_cmd(cmd:java + " -version 2>&1");
  }
  if(buf2)
  {
    buf2 = chomp(buf2);
    temp_buf = tolower(buf2);

    # determine if this is a java version we are interested in
    if ( ( "java version" >< temp_buf ) &&
         ( "ibm j9" >!< temp_buf ) &&
         ( "ibm (aix )?build" >!< temp_buf) &&
         ( "icedtea" >!< temp_buf ) &&
         ( "openjdk" >!< temp_buf ) &&
         ( "gij" >!< temp_buf )
       )
    {
      ver = eregmatch(pattern:'java version "(.*)"\n', string:temp_buf);
      if ( ver )
      {
        v = eregmatch(string: ver[1], pattern: "^(\d+\.\d+\.\d+)([^\d](\d+).*)$");
        if (v)
          ver_formatted = v[1]+'_'+v[3];
        else
        {
          v = eregmatch(string: ver[1], pattern: "^(\d+\.\d+\.\d+)$");
          if (v)
            ver_formatted = v[1]+'_0';
          else
            return FALSE;
        }
        return make_array('version',ver_formatted,'java',java);
      }
    }
  }
  return FALSE;
}

function safe_java_version(path,java,shell_path)
{
  local_var chkorcl_ptrn, version_ptrn, # grep patterns
            chkorcl_cmdt, version_cmdt, # command template to run
            chkorcl_file, version_file, # files to check
            chkorcl_resp, version_resp, # responses from commands
            exclude_cmdt, exclude_resp, # variables use to check if the rt.jar contains "openjdk / icedt / ect"
            exclude_ptrn,
            version,                    # parsed version
            chkjlib_resp,               # response from running ls path+"/lib/"
            libpath;                    # the path where the lib is, needed to find runtime

  if(isnull(shell_path))
    shell_path = "/bin/bash";

  # Figure out if we're dealing with JDK or JRE
  libpath = path+"/lib/";
  chkjlib_resp = run_cmd_template_wrapper(template:shell_path+' -c "ls $1$/rt.jar" 2>&1',args:make_list(libpath));
  if("no such file or directory" >< tolower(chkjlib_resp)) # Dealing with JDK
    libpath = path+"/jre/lib/";

  # Parse files for version information
  # The runtime (rt.jar) contains oracle / sun specific strings, the java binary
  # contains the version string itself
  chkorcl_ptrn = "'Implementation-Vendor: .*'";
  version_ptrn = "'[0-9]\.[0-9]\{1,2\}\.[0-9]\{1,2\}\(_[0-9]\{1,3\}\)\{0,1\}-b[0-9]\{1,2\}'";
  exclude_ptrn = "-i '(openjdk|icedt)'"; # IcedT / OpenJDK sometimes, erroneous 
  chkorcl_cmdt = shell_path+" -c "+'"'+"strings $1$ | grep -m 1 "+chkorcl_ptrn+'"';
  version_cmdt = shell_path+" -c "+'"'+"strings $1$ | grep -m 1 "+version_ptrn+'"';
  exclude_cmdt = shell_path+" -c "+'"'+"strings $1$ | grep -m 1 "+exclude_ptrn+'"';
  
  chkorcl_file = libpath+"rt.jar";
  version_file = java;
  # Stuff without strings by default
  if ( get_kb_item("Host/Ubuntu/release") || 
       get_kb_item("Host/Debian/release") || 
       get_kb_item("Host/SuSE/release")
  )
  {
    version_cmdt  = shell_path+" -c "+'"'+"grep -o -a "+version_ptrn+" $1$"+'"';
    chkorcl_cmdt  = shell_path+" -c "+'"'+"grep -o -a "+chkorcl_ptrn+" $1$"+'"';
    exclude_cmdt  = shell_path+" -c "+'"'+"grep -o -a "+exclude_ptrn+" $1$"+'"';
  }
  # Use egrep on solaris
  if ( get_kb_item("Host/Solaris/Version") || get_kb_item("Host/Solaris11/Version"))
  {
    chkorcl_ptrn = "'Implementation-Vendor: .*'";
    version_ptrn = "'[0-9]+\.[0-9]+\.[0-9]+(_[0-9]+)?-b[0-9]+'";
    chkorcl_cmdt = shell_path+" -c "+'"'+"strings $1$ | egrep "+chkorcl_ptrn+'"';
    version_cmdt = shell_path+" -c "+'"'+"strings $1$ | egrep "+version_ptrn+'"';
    exclude_cmdt = shell_path+" -c "+'"'+"strings $1$ | egrep "+exclude_ptrn+'"';
  }

  version_resp = run_cmd_template_wrapper(template:version_cmdt,args:make_list(version_file));
  chkorcl_resp = run_cmd_template_wrapper(template:chkorcl_cmdt,args:make_list(chkorcl_file));
  exclude_resp = run_cmd_template_wrapper(template:exclude_cmdt,args:make_list(chkorcl_file));

  #In some cases, the java binary is stripped out of java by namei
  #If that happened, try sending the command again with /bin/java appended
  if (!isnull(version_resp) && 'is a directory' >< tolower(version_resp))
  {
    java += '/bin/java';
    version_file += '/bin/java';
    version_resp = run_cmd_template_wrapper(template:version_cmdt,args:make_list(version_file));
  }

  #In some cases (web apps) it's rt.pack not rt.jar
  if (!isnull(chkorcl_resp) && 'no such file' >< tolower(chkorcl_resp))
  {
    chkorcl_file = libpath+"rt.pack";
    chkorcl_resp = run_cmd_template_wrapper(template:chkorcl_cmdt,args:make_list(chkorcl_file));
    exclude_resp = run_cmd_template_wrapper(template:exclude_cmdt,args:make_list(chkorcl_file));
  }

  if("icedt" >< tolower(exclude_resp) || "openjdk" >< tolower(exclude_resp))
  {
    return FALSE;
  }

  if(!version_resp)
  {
    return FALSE;
  }

  # Oracle bought Sun around ~ Java v1.5
  if(chkorcl_resp !~ "(Sun Microsystems, Inc.|Oracle Corporation)")
  {
    return FALSE;
  }

  # Parse and format version
  version = eregmatch(pattern:"(\d\.\d+\.\d+(_\d+)?)-b\d+", string:version_resp);

  if(isnull(version))
    return FALSE;

  version = version[1];
  if(version =~ "^\d+\.\d+\.\d+$")
    version += "_0";

  # Java bin location may have been updated: return both java and version
  return make_array("version", version, "java", java);
}

##
# Attempts to find java actively running in /proc/
##
function find_paths_in_proc()
{
  local_var fnd = make_array();
  local_var cmd = "ls -l /proc/*/exe 2> /dev/null | awk '/java/'";
  local_var buf = info_send_cmd(cmd:cmd);
  local_var line = NULL;

  if("command not found" >< buf)
    return make_list();

  buf = split(buf);
  foreach line (buf)
  {
    line = eregmatch(pattern:'exe[ \t]+->[ \t]+(.*java)$', string:line);
    if(!empty_or_null(line))
      fnd[line[1]] = TRUE;
  }
  return fnd;
}

#################
# Setup Section
################
dirs_to_check = "/opt/ /usr/";
shell_path = "/bin/bash";
# OSes unlikely to have bash
if(get_kb_item("Host/FreeBSD/release"))
  shell_path = "/bin/sh";
# OSes that frequently have find timeout because of large
# directory structures in /usr/
if(get_kb_item("Host/FreeBSD/release"))
  dirs_to_check = "/usr/lib/ /usr/lib34/ /usr/lib64/ /usr/bin/ /usr/sbin/ /usr/local/ /opt/";

# Only the following OSes are currently supported
unsupported = TRUE;
if ( get_kb_item("Host/CentOS/release") ||
     get_kb_item("Host/Debian/release") ||
     get_kb_item("Host/FreeBSD/release") ||
     get_kb_item("Host/Gentoo/release") ||
     get_kb_item("Host/HP-UX/version") ||
     get_kb_item("Host/Mandrake/release") ||
     get_kb_item("Host/RedHat/release") ||
     get_kb_item("Host/Slackware/release") ||
     get_kb_item("Host/Solaris/Version") ||
     get_kb_item("Host/Solaris11/Version") ||
     get_kb_item("Host/SuSE/release") ||
     get_kb_item("Host/Ubuntu/release") ||
     get_kb_item("Host/AIX/version")
  ) unsupported = FALSE;

# We want to use find_cmd(...) whenever possible
# however some OSes have versions of find that
# simply won't work with find_cmd so we fall back
# on regular old find
find_cmd_func_supported = TRUE;
if (
     get_kb_item("Host/Solaris/Version") ||
     get_kb_item("Host/Solaris11/Version") ||
     get_kb_item("Host/FreeBSD/release")
  ) find_cmd_func_supported = FALSE;

if (unsupported) exit(0, "Unix Java checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) audit(AUDIT_FN_UNDEF,"pread");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) audit(AUDIT_FN_FAIL,"ssh_open_connection");
 info_t = INFO_SSH;
}

info = "";
path_already_seen = make_array();
buf = NULL;
partial_find_results = FALSE;
found_with_proc = make_array();
is_proc_path = FALSE;

if (thorough_tests)
{

  if(find_cmd_func_supported)
  {
    buf = find_cmd(
      path_patterns : make_list("*/java"),
      start         : dirs_to_check,
      maxdepth      : NULL,
      timeout       : 320, # Half our total time
      exit_on_fail  : TRUE
    );
    # Find command returned something but also timedout
    # results may be partial
    partial_find_results = (!empty_or_null(buf[1]) && timedout);
  }
  # Can't use find_cmd or find_cmd failed or timedout without returning anything
  if(!find_cmd_func_supported || buf[0] != FIND_OK || (empty_or_null(buf[1]) && timedout))
  {
    command = "find "+dirs_to_check+" -type f -name java -print";
    #if targetting a HP-UX system, we need to use a slightly different command
    if (get_kb_item("Host/HP-UX/version")) command = "find "+dirs_to_check+" -type l -name java -print";
    buf = info_send_cmd(cmd:command);
  }
  else buf = buf[1]; # All good use these results

  # Also append any directories found via inspection of proc
  found_with_proc = find_paths_in_proc();
  foreach proc_path (keys(found_with_proc))
  {
    if(proc_path >!< buf)
      buf = proc_path+'\n'+buf;
    else
      found_with_proc[proc_path] = FALSE; # Already found this path ignore reporting the note about /proc/
  }
}
else
{
  if (
    get_kb_item("Host/HP-UX/version") ||
    get_kb_item("Host/Solaris/Version") ||
    get_kb_item("Host/Solaris11/Version") ||
    get_kb_item("Host/FreeBSD/release") ||
    get_kb_item("Host/AIX/version")
  ) command = "which java";
  else command = "which -a java";
  buf = info_send_cmd(cmd:command);
}

if ( buf && ('no java in' >!< buf && 'Command not found' >!< buf) )
{
  buf = chomp(buf);
  array = split(buf);
  foreach item (array)
  {

    item = chomp(item);
    # Did we find this path using /proc/ or find ?
    if(found_with_proc[item])
      is_proc_path = TRUE;
    else
      is_proc_path = FALSE;

    ##############################################################
    # Parse / normalize install path
    #
    item = resolve_symlink(item:item);

    path = item;
    # attempt to identify the install directory
    path = ereg_replace(pattern:"\/solr\/jre\/bin\/.*java$" , replace:"/", string:path);
    path = ereg_replace(pattern:"\/runtime\/jre\/bin\/.*java$" , replace:"/", string:path);
    path = ereg_replace(pattern:"\/jre\/bin\/.*java$" , replace:"/", string:path);
    if (path !~ '/usr/bin/java')
      path = ereg_replace(pattern:"\/bin\/.*java$" , replace:"/", string:path);
    path = chomp(path);
    # path could also be a symlink: try to resolve it
    path = resolve_symlink(item:path);
    # ensure that path ends in /
    if(path !~ "^.*/$") path += "/";

    # Optimization: skip paths containing openjdk
    # this isn't guaranteed to skip all openjdk
    # installs but at least we won't run expensive
    # commands against these dirs. 
    if ("openjdk" >< tolower(path))
      continue;

    ############################################################
    # Retrieve version information
    resp = FALSE;
    if (thorough_tests) # Paths came from find
      resp = safe_java_version(path:path,java:item,shell_path:shell_path);
    else # Paths came from which
      resp = java_version(java:item,shell_path:shell_path);

    # No version found for path / item -> next path / item
    if(!resp)
      continue;

    item = resp['java'];
    ver_formatted = resp['version'];

    ############################################################
    # More Path Normalization
    #
    # Note: we'd like to be more specific in the path
    # for things like Coldfusion, Signacert, tarantella,
    # so just remove not so much of the path
    if (
      "/solr/" >< item       ||
      "/runtime/" >< item    ||
      "/signacert/" >< item
    )
      path = ereg_replace(pattern:"\/bin\/.*java$" , replace:"/", string:item);

    if ("/tarantella/" >< item)
    {
      matches = eregmatch(
        string  :item,
        pattern :"^(\/.*tarantella\/.*\/jdk\.[^/]+\/(jre\/)?)bin\/java$",
        icase   : TRUE
      );
      if (matches)
        path = matches[1];
    }

    # path + version already seen -> next path / item
    if (path_already_seen[path+ver_formatted]++)
      continue;

    ############################################################
    # Determine if the managed
    #
    managed = 0;
    cmdtarg = make_list(item);
    # check to see if the install was installed via a native package management software
    if (get_kb_item("Host/RedHat/rpm-list"))
    {
      buf2 = run_cmd_template_wrapper(template:'rpm -qf $1$',args:cmdtarg);
      if ( buf2 )
        if ( ('-sun' >< buf2 || '-oracle' >< buf2) && ("is not owned by any package" >!< buf2) && ("No such file or directory" >!< buf2) )
          managed = 1;
    }
    else if ( get_kb_item("Host/HP-UX/swlist") )
    {
      # this may be a bit slow, eventually we may need to find a faster solution
      buf2 = run_cmd_template_wrapper(template:'find /var/adm/sw/products -name INFO -exec grep -il "$1$" {} \\;',args:cmdtarg);
      if ( buf2 )
        if ( "/var/adm/sw/products/" >< buf2 )
          managed = 1;
    }
    else if ( get_kb_item("Host/Solaris11/pkg-list") )
    {
      buf2 = run_cmd_template_wrapper(template:'pkg search -l -H -o pkg.name "$1$" && echo MANAGED',args:cmdtarg);
      if ( buf2 )
        if ( "MANAGED" >< buf2 )
          managed = 1;
    }
    else if ( get_kb_item("Host/Solaris/showrev") )
    {
      buf2 = run_cmd_template_wrapper(template:'pkgchk -l -p "$1$"',args:cmdtarg);
      if ( buf2 )
        if ( item >< buf2 )
          managed = 1;
    }
    else if ( get_kb_item("Host/AIX/lslpp") )
    {
      buf2 = run_cmd_template_wrapper(template:'lslpp -w "$1$"',args:cmdtarg);
      if ( buf2 )
        if ( item >< buf2 )
          managed = 1;
    }

    #######################################################
    # Register install information
    kb_str = "Host/Java/JRE/";
    if(oracle_bundled_java(javapath:path))
      kb_str += "Bundled/";
    else if (managed == 1)
      kb_str += "Managed/";
    else
      kb_str += "Unmanaged/";
    set_kb_item(name:kb_str+ver_formatted, value:path);

    register_install(
      app_name:"Oracle Java",
      path:path,
      version:ver_formatted,
      display_version:ver_formatted,
      cpe:"cpe:/a:oracle:jre");

    info += 
      '\n  Path    : ' + path + 
      '\n  Version : ' + ver_formatted;
    if(is_proc_path)
    {
       info +=
      '\n  Note    : This install was discovered by checking the currently'+
      '\n            running processes on the system, and it may not always'+
      '\n            be reported in future scans.';
    }
    info += '\n';
  }
}

# Report what we found.
if (info)
{
  set_kb_item(name:"Host/Java/JRE/Installed", value:TRUE);

  if (max_index(split(info)) > 3) s = "s of Oracle's JRE are";
  else s = " of Oracle's JRE is";

  report =
    '\n' +
    'The following instance'+s+' installed on the remote\n' +
    'host :\n' +
    info;

  if(thorough_tests && partial_find_results)
  {
    report += 
    '\n' +
    'Note: During execution it appears that the find command timed' +
    'out and may have only returned partial results.\n\n';
  }

  security_note(port: 0, extra: report);
}
else audit(AUDIT_NOT_INST, "Oracle Java");
