##
# (C) Tenable Network Security, Inc.
#
# macosx_software_eval_funcs.inc
# $Revision: 1.4 $
#
# @NOSOURCE@
##

##
# Find a managed package as seen by system_profiler, homebrew, or macports
#
# @param  string  argument:package REQUIRED package to search for and register
# @param  string  argument:cpe OPTIONAL cpe to register with register_install()
# @param  bool    argument:icase OPTIONAL search for package case insensitive
#                                                                default to TRUE
# @param  bool    argument:partial OPTIONAL search for partial package matches
#                                                                default to FALSE
# @param  bool    argument:single OPTIONAL save everything under the passed package name
#                                                                default to FALSE
# @remark  arguments are "package", "cpe", and "icase". This function will search for a
# @remark  package in the named var, and if found, returns a list of everything matching
# @remark  the pattern in "package" and registers the install.
#
# @return list  Returns a list of all packages found, FALSE if not found, NULL for anything else
##

function osx_find_installs(package,cpe,icase,partial,single)
{

  local_var return_val,pkg_app,pkg_version,pkg_ver_extra,pkg_location,sys_pkg,port_pkg;
  local_var AppPattern,package_list,pkg_record,pkg_field,field,pkg_count;
  local_var brew_pkg;
  local_var found_packages;
  local_var application_attributes,app_attribute,app_attr_match,extra_NR;

  return_val = NULL;
  found_packages=make_list();

  if(isnull(package))
  {
    err_print('osx_find_installs(): missing required arg : "package"');
    return NULL;
  }

  if (isnull(icase)) icase = TRUE;
  if (isnull(partial)) partial = FALSE;
  if (isnull(single)) single = FALSE;

  sys_pkg=get_kb_item_or_exit("MacOSX/packages/sys_profiler");
  brew_pkg=get_kb_item("MacOSX/packages/homebrew");
  port_pkg=get_kb_item("MacOSX/packages/macports");

  # Process applications found by system_profiler first - this should always be populated,
  # if not then something has gone horribly wrong, stop here, do not pass GO.
  # redundant or just being safe?
  if (isnull(sys_pkg)) return NULL;

  package_list = split(sys_pkg, sep:"|", keep:FALSE);
  if (isnull(package_list)) return NULL;

  if (partial)
    AppPattern='^Application: (.*?'+package+'.*?)\\037';
  else
    AppPattern='^Application: ('+package+')\\037';

  pkg_count=0;

  foreach pkg_record (package_list)
  {
    pkg_app = NULL;
    pkg_version = NULL;
    pkg_location = NULL;

    pkg_count++;
    pkg_app = eregmatch(pattern:AppPattern, string:pkg_record, icase:icase);

    if ( !isnull(pkg_app[1]) )
    {
      pkg_location = eregmatch(pattern:"Location: (.*?)\037", string:pkg_record, icase:TRUE);
      pkg_version = eregmatch(pattern:"Version: (.*?)\037", string:pkg_record, icase:TRUE);

      if(empty_or_null(pkg_version[1]))
        pkg_version[1]="unknown";
      if(empty_or_null(pkg_location[1]))
        pkg_location[1]="/Unknown"+pkg_count+"/";

      # Take rest of the attributes returned by system_profiler and store them in extra_no_report
      extra_NR=make_array();
      application_attributes=split(pkg_record, sep:raw_string(0x1F), keep:FALSE);
      if ( !empty_or_null(application_attributes) )
      {
        foreach app_attribute (application_attributes)
        {
          if ((app_attribute !~ "^Application: " ) &&
             ( app_attribute !~ "^Version: " ) &&
             ( app_attribute !~ "^Location: " ))
          {
            app_attr_match=eregmatch(pattern:"(.*?): (.*)",string:app_attribute);
            if ( !empty_or_null(app_attr_match) )
              extra_NR[app_attr_match[1]] = app_attr_match[2];
          }
        }
      }

      if (single)
      {
        extra_NR["name"] = pkg_app[1];
        register_install(
          app_name:package,
          path:pkg_location[1],
          version:pkg_version[1],
          cpe:cpe,
          extra_no_report:extra_NR
        );
      }
      else
        register_install(
          app_name:pkg_app[1],
          path:pkg_location[1],
          version:pkg_version[1],
          cpe:cpe,
          extra_no_report:extra_NR
        );
      found_packages = list_uniq(make_list(found_packages,pkg_app[1]));
    }
  }

  if (max_index(found_packages) == 0)
    return_val=FALSE;
  else
    return_val=found_packages;

  # Process applications found and managed by homebrew
  if (!isnull(brew_pkg))
  {
    package_list = split(brew_pkg,sep:"|", keep:FALSE);

    foreach pkg_record (package_list)
    {
      pkg_app = NULL;
      pkg_location = NULL;
      pkg_version = "unknown";

      pkg_field = split(pkg_record, sep:' ', keep:FALSE);

      if(empty_or_null(pkg_field)) continue;

      #counter to use for paths in case its not registered correctly
      pkg_count++;
      pkg_app=pkg_field[0];
      pkg_version=pkg_field[1];

      # if package is found, then location is in the location
      # MacOSX/homebrew/cellar"+"/"+pkg_app+pkg_version
      # $ brew info openssl | grep $Cellar
      #   /usr/local/Cellar/openssl/1.0.1j_1 (431 files, 15M)

      if ( ereg(string:pkg_app,pattern:package, icase:icase))
      {
        pkg_location=get_kb_item("MacOSX/homebrew/cellar");
        if (!empty_or_null(pkg_location)) 
          pkg_location=pkg_location+"/"+pkg_app+"/"+pkg_version;
        else
          pkg_location="Unknown"+"/";

        if (single)
          register_install(
            app_name:package,
            path:pkg_location,
            version:pkg_version,
            cpe:cpe,
            extra_no_report:make_array("name", pkg_app)
          );
        else
          register_install(
            app_name:pkg_app,
            path:pkg_location,
            version:pkg_version,
            cpe:cpe
          );
        # Append to found_packages list
        found_packages = list_uniq(make_list(found_packages,pkg_app));
      }
    }

    # return_val is defaulted to FALSE, so if found_packages is already 
    # defined and populated, simply update the return_val
    if (max_index(found_packages) != 0)
      return_val=found_packages;

  } # End homebrew processing

  # Process applications found and managed by MacPorts
  if (!isnull(port_pkg))
  {
    package_list = split(port_pkg,sep:"|", keep:FALSE);

    foreach pkg_record (package_list)
    {
      pkg_app=NULL;
      pkg_location=NULL;
      pkg_version=NULL;

      pkg_field = split(pkg_record, sep:' ',keep:FALSE);

      if(empty_or_null(pkg_field)) continue;

      if ( ereg(string:pkg_field[0],pattern:package,icase:icase) )
      {
        # we only look for macports in the default location at this point
        pkg_location="/opt/local";

        # The version in pkg_field[1] may be in the format
        #  @5.12.4_0+perl5_16 where the 'variant' after the '+'
        # is optional

        pkg_version=eregmatch(string:pkg_field[1],pattern:"^@([^+]+)(\+(.+))?$",icase:TRUE);
        if (empty_or_null(pkg_version))
          pkg_version="unknown";

        if (!empty_or_null(pkg_version[3]))
          pkg_ver_extra=make_array("Variant",pkg_version[3]);
        else
          pkg_ver_extra=make_array("Variant","None");

        pkg_app = ereg_replace(pattern:"^\s*([^\s].*[^\s]|[^\s])\s*$", replace:"\1", string:pkg_field[0]);

        if (single)
          register_install(
            app_name:package,
            path:pkg_location,
            version:pkg_version[1],
            extra:pkg_ver_extra,
            cpe:cpe,
            extra_no_report:make_array("name",pkg_app)
          );
        else
          register_install(
            app_name:pkg_app,
            path:pkg_location,
            version:pkg_version[1],
            extra:pkg_ver_extra,
            cpe:cpe
          );
      # Append to found packages list
      found_packages = list_uniq(make_list(found_packages,pkg_field[0]));
      }
    }

    if ( max_index(found_packages) !=0 )
      return_val=found_packages;

  } # End MacPorts processing

  return return_val;
}
