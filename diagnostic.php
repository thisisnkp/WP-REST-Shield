<?php
/**
 * WP REST Shield Diagnostic Tool
 * Upload this file to your WordPress root directory and access it via browser
 * URL: https://stage.learnelite.in/diagnostic.php
 */

// Load WordPress
require_once('wp-load.php');

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>WP REST Shield Diagnostics</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0073aa; padding-bottom: 10px; }
        h2 { color: #0073aa; margin-top: 30px; border-bottom: 2px solid #eee; padding-bottom: 8px; }
        .success { background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #28a745; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #dc3545; }
        .warning { background: #fff3cd; color: #856404; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #ffc107; }
        .info { background: #d1ecf1; color: #0c5460; padding: 10px; border-radius: 4px; margin: 10px 0; border-left: 4px solid #17a2b8; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; border: 1px solid #dee2e6; }
        code { background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-size: 90%; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; color: #333; }
        tr:hover { background-color: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-success { background: #28a745; color: white; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #333; }
        .test-url { background: #e9ecef; padding: 8px; border-radius: 4px; font-family: monospace; margin: 5px 0; }
        .copy-btn { cursor: pointer; padding: 4px 8px; background: #0073aa; color: white; border: none; border-radius: 4px; margin-left: 10px; }
        .copy-btn:hover { background: #005a87; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ WP REST Shield Diagnostic Report</h1>
    <p><strong>Generated:</strong> <?php echo current_time('Y-m-d H:i:s'); ?></p>

<?php
// 1. Check if plugin is installed
echo "<h2>1. Plugin Installation Check</h2>";

$plugin_file = WP_PLUGIN_DIR . '/wp-rest-shield/wp-rest-shield.php';
if (file_exists($plugin_file)) {
    echo "<div class='success'>✅ Plugin file found: <code>$plugin_file</code></div>";
} else {
    echo "<div class='error'>❌ Plugin file NOT found: <code>$plugin_file</code></div>";
    echo "<div class='warning'>⚠️ Please ensure the plugin is uploaded to the correct directory.</div>";
}

// Check if plugin is active
$active_plugins = get_option('active_plugins', []);
$is_active = in_array('wp-rest-shield/wp-rest-shield.php', $active_plugins);

if ($is_active) {
    echo "<div class='success'>✅ Plugin is ACTIVE</div>";
} else {
    echo "<div class='error'>❌ Plugin is NOT active</div>";
    echo "<div class='warning'>⚠️ Please activate the plugin in WordPress Admin → Plugins</div>";
}

// 2. Check if classes exist
echo "<h2>2. Class Loading Check</h2>";

$classes_to_check = [
    'WPRestShield\API\TokenEndpoint',
    'WPRestShield\API\TokenEndpointV2',
    'WPRestShield\Core\RestFilter',
    'WPRestShield\Core\JWT',
    'WPRestShield\Core\Plugin',
];

foreach ($classes_to_check as $class) {
    if (class_exists($class)) {
        echo "<div class='success'>✅ Class loaded: <code>$class</code></div>";
    } else {
        echo "<div class='error'>❌ Class NOT loaded: <code>$class</code></div>";

        // Try to find the file
        $file_path = str_replace('WPRestShield\\', '', $class);
        $file_path = WP_PLUGIN_DIR . '/wp-rest-shield/includes/' . str_replace('\\', '/', $file_path) . '.php';

        if (file_exists($file_path)) {
            echo "<div class='warning'>⚠️ File exists but class not loaded: <code>$file_path</code></div>";
            echo "<div class='info'>💡 There might be a PHP syntax error in this file. Check error logs.</div>";
        } else {
            echo "<div class='error'>❌ File does NOT exist: <code>$file_path</code></div>";
        }
    }
}

// 3. Check REST API
echo "<h2>3. REST API Configuration</h2>";

$rest_url_base = rest_url();
echo "<div class='info'>📍 REST API Base URL: <code>$rest_url_base</code></div>";

// Check if REST API is enabled
if (function_exists('rest_get_server')) {
    echo "<div class='success'>✅ REST API is enabled</div>";

    $server = rest_get_server();
    $all_routes = $server->get_routes();

    echo "<div class='info'>📊 Total registered routes: <strong>" . count($all_routes) . "</strong></div>";

    // Check for wp-rest-shield routes
    $v1_routes = [];
    $v2_routes = [];
    $other_shield_routes = [];

    foreach ($all_routes as $route => $data) {
        if (strpos($route, '/wp-rest-shield/v1') === 0) {
            $v1_routes[] = $route;
        } elseif (strpos($route, '/wp-rest-shield/v2') === 0) {
            $v2_routes[] = $route;
        } elseif (strpos($route, '/wp-rest-shield') === 0) {
            $other_shield_routes[] = $route;
        }
    }

    echo "<h3>WP REST Shield Routes Status</h3>";

    if (count($v1_routes) > 0) {
        echo "<div class='success'>✅ V1 Routes Found: <strong>" . count($v1_routes) . "</strong></div>";
        echo "<table><tr><th>Route</th><th>Methods</th></tr>";
        foreach ($v1_routes as $route) {
            $methods = array_keys($all_routes[$route]);
            echo "<tr><td><code>$route</code></td><td>" . implode(', ', $methods) . "</td></tr>";
        }
        echo "</table>";
    } else {
        echo "<div class='error'>❌ No V1 routes found!</div>";
    }

    if (count($v2_routes) > 0) {
        echo "<div class='success'>✅ V2 Routes Found: <strong>" . count($v2_routes) . "</strong></div>";
        echo "<table><tr><th>Route</th><th>Methods</th></tr>";
        foreach ($v2_routes as $route) {
            $methods = array_keys($all_routes[$route]);
            echo "<tr><td><code>$route</code></td><td>" . implode(', ', $methods) . "</td></tr>";
        }
        echo "</table>";
    } else {
        echo "<div class='error'>❌ No V2 routes found!</div>";
    }

    if (count($other_shield_routes) > 0) {
        echo "<div class='warning'>⚠️ Other shield routes: " . count($other_shield_routes) . "</div>";
    }

} else {
    echo "<div class='error'>❌ REST API is NOT enabled or not available</div>";
}

// 4. Check file structure
echo "<h2>4. File Structure Check</h2>";

$files_to_check = [
    'wp-rest-shield.php',
    'includes/API/TokenEndpoint.php',
    'includes/API/TokenEndpointV2.php',
    'includes/Core/RestFilter.php',
    'includes/Core/JWT.php',
    'includes/Core/Plugin.php',
    'includes/Admin/AdminPage.php',
];

echo "<table><tr><th>File</th><th>Status</th><th>Size</th><th>Modified</th></tr>";
foreach ($files_to_check as $file) {
    $full_path = WP_PLUGIN_DIR . '/wp-rest-shield/' . $file;
    if (file_exists($full_path)) {
        $size = filesize($full_path);
        $modified = date('Y-m-d H:i:s', filemtime($full_path));
        echo "<tr>";
        echo "<td><code>$file</code></td>";
        echo "<td><span class='badge badge-success'>EXISTS</span></td>";
        echo "<td>" . number_format($size) . " bytes</td>";
        echo "<td>$modified</td>";
        echo "</tr>";
    } else {
        echo "<tr>";
        echo "<td><code>$file</code></td>";
        echo "<td><span class='badge badge-danger'>MISSING</span></td>";
        echo "<td colspan='2'>File not found</td>";
        echo "</tr>";
    }
}
echo "</table>";

// 5. Test endpoints
echo "<h2>5. Endpoint Testing</h2>";

$test_endpoints = [
    'V1 Health Check' => rest_url('wp-rest-shield/v1/health'),
    'V2 Health Check' => rest_url('wp-rest-shield/v2/health'),
    'V1 Token' => rest_url('wp-rest-shield/v1/token'),
    'V2 Token' => rest_url('wp-rest-shield/v2/token'),
    'V2 Docs' => rest_url('wp-rest-shield/v2/docs'),
];

echo "<p>Test these URLs in your browser or API client:</p>";
foreach ($test_endpoints as $name => $url) {
    echo "<div class='test-url'>";
    echo "<strong>$name:</strong><br>";
    echo "<a href='$url' target='_blank'>$url</a>";
    echo "<button class='copy-btn' onclick='copyToClipboard(\"$url\")'>Copy</button>";
    echo "</div>";
}

// 6. Check WordPress version
echo "<h2>6. Environment Information</h2>";

global $wp_version;
echo "<table>";
echo "<tr><th>Item</th><th>Value</th></tr>";
echo "<tr><td>WordPress Version</td><td>$wp_version</td></tr>";
echo "<tr><td>PHP Version</td><td>" . phpversion() . "</td></tr>";
echo "<tr><td>Site URL</td><td>" . get_site_url() . "</td></tr>";
echo "<tr><td>Home URL</td><td>" . get_home_url() . "</td></tr>";
echo "<tr><td>REST URL</td><td>" . rest_url() . "</td></tr>";
echo "<tr><td>Permalink Structure</td><td>" . get_option('permalink_structure', 'Plain') . "</td></tr>";
echo "</table>";

// 7. Check for PHP errors
echo "<h2>7. Recent PHP Errors</h2>";

if (defined('WP_DEBUG') && WP_DEBUG) {
    echo "<div class='success'>✅ WP_DEBUG is enabled</div>";

    $debug_file = WP_CONTENT_DIR . '/debug.log';
    if (file_exists($debug_file)) {
        echo "<div class='info'>📝 Debug log found: <code>$debug_file</code></div>";

        // Get last 50 lines
        $lines = file($debug_file);
        $recent_lines = array_slice($lines, -50);

        $shield_errors = array_filter($recent_lines, function($line) {
            return stripos($line, 'rest-shield') !== false || stripos($line, 'WPRestShield') !== false;
        });

        if (count($shield_errors) > 0) {
            echo "<div class='error'>⚠️ Found plugin-related errors in debug log:</div>";
            echo "<pre>" . htmlspecialchars(implode('', $shield_errors)) . "</pre>";
        } else {
            echo "<div class='success'>✅ No plugin-related errors in recent logs</div>";
        }
    } else {
        echo "<div class='warning'>⚠️ Debug log file not found</div>";
    }
} else {
    echo "<div class='warning'>⚠️ WP_DEBUG is disabled. Enable it in wp-config.php to see errors:</div>";
    echo "<pre>define('WP_DEBUG', true);\ndefine('WP_DEBUG_LOG', true);\ndefine('WP_DEBUG_DISPLAY', false);</pre>";
}

// 8. Action Items
echo "<h2>8. Recommended Actions</h2>";

$actions = [];

if (!$is_active) {
    $actions[] = "Activate the plugin in WordPress Admin → Plugins";
}

if (count($v1_routes) === 0 && count($v2_routes) === 0) {
    $actions[] = "Routes are not registered. Try flushing permalinks: Settings → Permalinks → Save Changes";
    $actions[] = "Deactivate and reactivate the plugin";
    $actions[] = "Check for PHP syntax errors in the plugin files";
}

if (!class_exists('WPRestShield\API\TokenEndpointV2')) {
    $actions[] = "Ensure TokenEndpointV2.php is uploaded to: includes/API/TokenEndpointV2.php";
}

if (count($actions) > 0) {
    echo "<ol>";
    foreach ($actions as $action) {
        echo "<li class='warning'>$action</li>";
    }
    echo "</ol>";
} else {
    echo "<div class='success'>✅ Everything looks good! Routes should be working.</div>";
}

?>

<script>
function copyToClipboard(text) {
    const temp = document.createElement('textarea');
    temp.value = text;
    document.body.appendChild(temp);
    temp.select();
    document.execCommand('copy');
    document.body.removeChild(temp);
    alert('Copied: ' + text);
}
</script>

<hr style="margin: 40px 0;">
<p style="text-align: center; color: #666;">
    <strong>Diagnostic Tool for WP REST Shield</strong><br>
    Delete this file after troubleshooting for security reasons.
</p>

</div>
</body>
</html>
