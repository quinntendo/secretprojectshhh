<?php

/**
 * Make an array of references to the values of another array
 * Note: useful when references rather than values are required
 * @param {array} array of values
 * @return {array} references array
 */
function makeRefArr(&$arr) {
    $refs = array();

    foreach ($arr as $key => &$val) {
	$refs[$key] = &$val;
    }

    return $refs;
}

/**
 * Make a recursive copy of an array
 * @param {array} original array
 * @param {boolean} should the values to be cloned too?
 * @return {array} copy of source array
 */
function array_copy($arr, $deep = true) {
    $newArr = array();

    if ($deep) {
	foreach ($arr as $key => $val) {
	    if (is_object($val)) {
		$newArr[$key] = clone($val);
	    } else if (is_array($val)) {
		$newArr[$key] = array_copy($val);
	    } else {
		$newArr[$key] = $val;
	    }
	}
    } else {
	foreach ($arr as $key => $val) {
	    $newArr[$key] = $val;
	}
    }

    return $newArr;
}

/**
 * A mysqli wrapper class
 *
 * @author Andrew Lowndes (APL Web)
 * @date 20/11/2010
 */
class DbBase {

    const DUPLICATE_KEY_ERRNO = 1062;

    private static $dbs = null;

    //connect to the database
    public static function connect(
	    $host = null,
	    $user = null,
	    $pass = null,
	    $name = null) {
	if (is_null(self::$dbs)) {
	    self::$dbs = array();
	}
	if (isset(self::$dbs[get_called_class()])) {
	    return;
	}
	self::$dbs[get_called_class()] = new mysqli(
		is_null($host) ? DB_HOST : $host,
		is_null($user) ? DB_USER : $user,
		is_null($pass) ? DB_PASS : $pass,
		is_null($name) ? DB_NAME : $name);

	if (mysqli_connect_errno()) {
	    throw new Exception('Connection failed: ' . mysqli_connect_error());
	}
	//self::$dbs[get_called_class()]->query("SET time_zone = 'US/Eastern'");
	self::$dbs[get_called_class()]->query("SET NAMES 'utf8'");
	self::$dbs[get_called_class()]->query("SET CHARACTER SET utf8");
	//self::$dbs[get_called_class()]->set_charset("utf8");
    }

    //close the connection
    public static function close() {
	if (self::$dbs[get_called_class()]) {
	    self::$dbs[get_called_class()]->close();
	}
    }

    //close the connection
    public static function disconnect() {
	self::close();
    }

    // Shit, dont' know which of these is being used. 
    //get mysqli db class
    public static function db() {
	return self::$dbs[get_called_class()];
    }

    //get mysqli db class
    public static function getDb() {
	return self::$dbs[get_called_class()];
    }

    /**
     * Run a query and return the result
     * @param {string} query to run (with '?' for values)
     * @param {array} values to execute in prepared statement (optional)
     * @return {resource} result
     */
    public static function query($query, $objs = array()) {
	if (!self::$dbs[get_called_class()]) {
	    $x = new Exception();
	    $stackTrace = $x->getTraceAsString();
	    error_log($stackTrace);
	    error_log('Connection not established.');
	    throw new Exception('Connection not established.');
	}

	$objs = (array) $objs; //automagically cast single values into an array
	//error_log("Query: '$query'");
	$statement = self::$dbs[get_called_class()]->prepare($query);
	if (!$statement) {
	    $x = new Exception();
	    $stackTrace = $x->getTraceAsString();
	    error_log(self::$dbs[get_called_class()]->error);
	    error_log($stackTrace);
	    throw new Exception('Query failed: ' . self::$dbs[get_called_class()]->error);
	}

	//go through all of the provided objects and bind them
	$types = array();
	$values = array();

	if (count($objs) > 0) {
	    foreach ($objs as $obj) {
		//get the object type and translate it ready for bind parameter
		$type = gettype($obj);

		switch ($type) {
		    case 'boolean': case 'integer':
			$types[] = 'i';
			$values[] = intval($obj);
			break;
		    case 'double':
			$types[] = 'd';
			$values[] = doubleval($obj);
			break;
		    case 'string':
			$types[] = 's';
			$values[] = (string) $obj;
			break;
		    case 'array': case 'object':
			$paramTypes[] = 's';
			$values[] = json_encode($obj);
			break;
		    case 'null':
		    case 'NULL':
			$types[] = 's';
			$values[] = NULL;
			break;
		    case 'resource': case 'unknown type': default:
			$x = new Exception();
			$stackTrace = $x->getTraceAsString();
			error_log($stackTrace);
			throw new Exception("Unsupported object passed through as query prepared object!\n");
		    //throw new Exception('Unsupported object passed through as query prepared object!');
		}
	    }

	    $params = makeRefArr($values);
	    array_unshift($params, implode('', $types));
	    call_user_func_array(array($statement, 'bind_param'), $params);
	}

	// TEMP TEST CODE TO SEE ALL QUERIES WITH ARGS ATTACHED
	if (QUERY_DEBUG) {
	    $tmpQuery = $query;
	    foreach ($objs as $p) {
		$tmpQuery = preg_replace('/\?/', "'$p'", $tmpQuery, 1);
	    }
	    $tmpQuery = preg_replace('/\n/', '', $tmpQuery);
	    $tmpQuery = preg_replace('/\t/', '', $tmpQuery);
	    error_log("QUERY: " . $tmpQuery);
	    if (QUERY_DEBUG_STACKTRACE) {
		error_log(print_r(debug_backtrace(), true));
	    }
	}

	$res = $statement->execute();

	if (!$res) {
	    $x = new Exception();
	    $stackTrace = $x->getTraceAsString();
	    error_log(self::$dbs[get_called_class()]->error);
	    error_log($stackTrace);
	    throw new Exception($statement->error, $statement->errno);
	}

	$statement->store_result();
	return $statement;
    }

    /**
     * Determine if an object exists
     * @param {string} query to run
     * @param {array} objects to use in prepare query (optional)
     * @return {boolean} object exists in database
     */
    public static function objectExists($query, $objs = array()) {
	$statement = self::query($query, $objs);

	return (is_object($statement) && $statement->num_rows > 0);
    }

    /**
     * Make an associative array of field names from a statement
     * @param {resource} mysqli statement
     * @return {array} field names array
     */
    private static function getFieldNames($statement) {
	$result = $statement->result_metadata();
	$fields = $result->fetch_fields();

	$fieldNames = array();
	foreach ($fields as $field) {
	    $fieldNames[$field->name] = null;
	}

	return $fieldNames;
    }

    /**
     * Get an object from a query
     * @param {string} query to execute
     * @param {array} objects to use as the values (optional)
     * @return {assoc} sinulatobject
     */
    public static function getObject($query, $objs = array()) {
	$statement = self::query($query, $objs);

	if (!is_object($statement) || $statement->num_rows < 1) {
	    return null;
	}

	$fieldNames = self::getFieldNames($statement);
	call_user_func_array(array($statement, 'bind_result'), makeRefArr($fieldNames));

	$statement->fetch();
	$statement->close();

	return $fieldNames;
    }

    /**
     * Get a list of objects from the database
     * @param {string} query
     * @return {array} objects
     */
    public static function getObjects($query, $objs = array()) {
	$statement = self::query($query, $objs);

	if (!is_object($statement) || $statement->num_rows < 1) {
	    return array();
	}

	$fieldNames = self::getFieldNames($statement);
	call_user_func_array(array($statement, 'bind_result'), makeRefArr($fieldNames));

	$results = array();
	while ($statement->fetch()) {
	    $results[] = array_copy($fieldNames);
	}

	$statement->close();

	return $results;
    }

    public static function getTypedObject($query, $objs = array(), $clazz = stdclass, $camelFlag = true) {
	if (!class_exists($clazz)) {
	    throw new Exception('Unknown class: ' . $clazz);
	}

	$recordData = self::getObject($query, $objs);
	if (is_null($recordData)) {
	    return null;
	}

	$typedObj = new $clazz();
	if ($camelFlag) {
	    foreach ($recordData as $column => $value) {
		$column = underscoreToCamelCase($column);
		$typedObj->$column = $value;
	    }
	} else {
	    foreach ($recordData as $column => $value) {
		$typedObj->$column = $value;
	    }
	}

	return $typedObj;
    }

    public static function getTypedObjects($query, $objs = array(), $clazz = stdClass, $camelFlag = true) {
	$statement = self::query($query, $objs);

	if (!is_object($statement) || $statement->num_rows < 1) {
	    return array();
	}

	$fieldNames = self::getFieldNames($statement);
	call_user_func_array(array($statement, 'bind_result'), makeRefArr($fieldNames));

	$results = array();
	while ($statement->fetch()) {
	    $recordData = array_copy($fieldNames);

	    $typedObj = new $clazz();
	    if ($camelFlag) {
		foreach ($recordData as $column => $value) {
		    $column = underscoreToCamelCase($column);
		    $typedObj->$column = $value;
		}
	    } else {
		foreach ($recordData as $column => $value) {
		    $typedObj->$column = $value;
		}
	    }

	    $results[] = $typedObj;
	}

	$statement->close();

	return $results;
    }

    /**
     * Get all of the data from a table
     * @param {string} table name
     * @return {array} table data
     */
    public static function getTable($tableName) {
	if (!self::$dbs[get_called_class()]) {
	    throw new Exception('Connection not established.');
	}

	$tableName = self::$dbs[get_called_class()]->escape_string($tableName);

	return self::getObjects('SELECT * FROM `' . $tableName . '`;');
    }

    /**
     * Get a field from a table based on a field having a specific value
     * @param {string} table name
     * @param {string} field name
     * @param {mixed} field value
     * @return {array} table row data
     */
    public static function getTableRow($tableName, $field, $value) {
	if (!self::$dbs[get_called_class()]) {
	    throw new Exception('Connection not established.');
	}

	$tableName = self::$dbs[get_called_class()]->escape_string($tableName);
	$field = self::$dbs[get_called_class()]->escape_string($field);

	return self::getObject('SELECT * FROM `' . $tableName . '` WHERE `' . $field . '` = ? LIMIT 1;', $value);
    }

    /**
     * Get all related rows from a table based on a field having a specific value
     * @param {string} table name
     * @param {string} field name
     * @param {mixed} field value
     * @return {array} table row data
     */
    public static function getTableRows($tableName, $field, $value, $sortField = null, $sortDesc = false) {
	if (!self::$dbs[get_called_class()]) {
	    throw new Exception('Connection not established.');
	}

	$tableName = self::$dbs[get_called_class()]->escape_string($tableName);
	$field = self::$dbs[get_called_class()]->escape_string($field);

	if ($sortField == null) {
	    $sortField = $field;
	} else {
	    $sortField = self::$dbs[get_called_class()]->escape_string($sortField);
	}

	return self::getObjects('SELECT * FROM `' . $tableName . '` WHERE `' . $field . '` = ? ORDER BY `' . $sortField . '` ' . ($sortDesc ? 'DESC' : 'ASC') . ';', $value);
    }

    /**
     * Builds a mapping on a given $field (Result is a dictionary of objects mapped to $field).
     */
    public static function getTypedMap($field, $query, $objs = array(), $clazz = stdClass, $camelFlag = true) {
	$objects = self::getTypedObjects($query, $objs, $clazz, $camelFlag);
	$result = array();
	foreach ($objects as $obj) {
	    $result[$obj->$field] = $obj;
	}

	return $result;
    }

}

?>
