<?php
/**
 * Extension to authenticate against an external Django Auth Database.
 *
 *
 * Add the following code into LocalSettings.php:
 * // Required:
 * $wgDjangoAuthDB_Database = '';
 * $wgDjangoAuthDB_Username = '';
 * $wgDjangoAuthDB_Password = '';
 * // Optional:
 * //$wgDjangoAuthDB_Host = 'localhost';
 * //$wgDjangoAuthDB_Driver = 'mysql' or 'pgsql';
 * require_once("$IP/extensions/DjangoAuthDB/DjangoAuthDB.php");
 * $wgAuth = new DjangoAuthDB();
 *
 */

$wgExtensionCredits['parserhook'][] = array (
  'path' => __FILE__,
  'name' => 'DjangoAuthDB',
  'author' => 'Andreas Nüßlein <andreas@nuessle.in>',
  'description' => 'Authenticate users against an external Django Auth',
  'url' => 'https://github.com/nutztherookie/mediawiki-DjangoAuthDB',
  'version' => '0.1',
);


require_once ( 'includes/AuthPlugin.php' );
class DjangoAuthDB extends AuthPlugin {

  private function connectToDB() {
    $db_name = $GLOBALS['wgDjangoAuthDB_Database'];
    $db_user = $GLOBALS['wgDjangoAuthDB_Username'];
    $db_password = $GLOBALS['wgDjangoAuthDB_Password'];
    $db_host = (isset($GLOBALS['wgDjangoAuthDB_Host'])) ? $GLOBALS['wgDjangoAuthDB_Host'] : 'localhost';
    $db_driver = (isset($GLOBALS['wgDjangoAuthDB_Driver'])) ? $GLOBALS['wgDjangoAuthDB_Driver'] : 'mysql';
    $dsn = "${db_driver}:host=${db_host};dbname=${db_name}";

    try {
      $db = new PDO($dsn, $db_user, $db_password);
    } catch (PDOException $e) {
      wfDebug("DjangoAuthDB::connectToDB() : DB failed to open\n");
    }
    return $db;
  }

  function userExists( $username ) {
    $db = $this->connectToDB();
    $sql = 'SELECT username FROM auth_user WHERE username = :username';
    $sth = $db->prepare($sql);
    if ($sth->execute(array(':username' => $username))) {
      $row = $sth->fetch();
      return !empty($row);
    }
    return false;
  }

  function authenticate( $username, $password ) {
    $db = $this->connectToDB();
    $sql = 'SELECT username FROM auth_user WHERE username = :username';
    $sql .= ' AND is_active';
    $sql .= ' AND SUBSTRING_INDEX(password,"$",-1) = SHA1(CONCAT(SUBSTRING_INDEX(SUBSTRING(password,6),"$",1),:password))';
    $sth = $db->prepare($sql);
    if ($sth->execute(array(':username' => $username, ':password' => $password))) {
      $row = $sth->fetch();
      return !empty($row);
    }
    return false;
  }

  function updateUser( &$user ) {
    $db = $this->connectToDB();
    $sql = 'SELECT * FROM auth_user WHERE username = :username';
    $sth = $db->prepare($sql);
    if ($sth->execute(array(':username' => $user->mName))) {
        $row = $sth->fetch();
        $user->setEmail($row['email']);
        $user->setRealName($row['first_name']." ".$row['last_name']);
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
    }
    return true;
  }

  /* This function doesn't seem to exist anymore in the current mediawiki 
  function disallowPrefsEditByUser() {
    return array (
      'wpRealName' => true,
      'wpUserEmail' => true,
      'wpNick' => true
    );
  }
   */


  /**
   * Return true if the wiki should create a new local account automatically
   * when asked to login a user who doesn't exist locally but does in the
   * external auth database.
   *
   * If you don't automatically create accounts, you must still create
   * accounts in some way. It's not possible to authenticate without
   * a local account.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @public
   */
  function autoCreate() {
    return true;
  }

  /**
   * Can users change their passwords?
   *
   * @return bool
   */
  function allowPasswordChange() {
    return false;
  }

  /**
   * Add a user to the external authentication database.
   * Return true if successful.
   *
   * @param User $user - only the name should be assumed valid at this point
   * @param string $password
   * @param string $email
   * @param string $realname
   * @return bool
   * @public
   */
  function addUser( $user, $password, $email='', $realname='' ) {
    return false;
  }

  /**
   * Return true to prevent logins that don't authenticate here from being
   * checked against the local database's password fields.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @public
   */
  function strict() {
    return true;
  }

}
