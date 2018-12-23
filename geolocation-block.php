<?php
/**
 * @package Geolocation_Block
 * @version 1.6
 */
/*
Plugin Name: Geolocation Block
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: 
Author: Xavi Nguyen
Version: 1.6
Author URI: https://sundaysea.com
*/


use Location\Coordinate;
use Location\Polygon;
require_once __DIR__ . '/vendor/autoload.php';


define ('GEOLOCATION_BLOCK_API_KEY', 'AIzaSyBe1PR1CbV5B-ANVEHynHXYHAJ8GofAIhc');

class Geolocation_Block_Page {

	function __construct() {
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
	}

	function admin_menu() {
		add_options_page(
			'Page Title',
			'Geolocation Block',
			'manage_options',
			'Geolocation_Block_Page',
			array(
				$this,
				'settings_page'
			)
		);
	}

	function  settings_page() {
		if (!empty($_POST)) { 
			file_put_contents(__DIR__ . '/geojsons/city1.json', json_encode($_POST['city1']));
			file_put_contents(__DIR__ . '/geojsons/city2.json', json_encode($_POST['city2']));
			file_put_contents(__DIR__ . '/geojsons/city3.json', json_encode($_POST['city3'])); 
		}
		
		$geolocationData = json_decode(get_option('geolocation_block_city_data'), true);
		
		ob_start();
		?>
		   <script src="http://maps.googleapis.com/maps/api/js?sensor=false&amp;libraries=places&key=<?php echo GEOLOCATION_BLOCK_API_KEY; ?>"></script>
		   
    <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>

		  <script src="<?php echo plugin_dir_url( __FILE__ ) . 'js/geocomplete.js'; ?>"></script>
		  <p>
You can get polygon coordenates in json for using with googlemaps using openstreetmap. Go to <a href='http://nominatim.openstreetmap.org/'>http://nominatim.openstreetmap.org/</a> search a place like "Partido de Ituzaingó"
<br>
click on "details"
<br>
Look for OSM ID and copy it (control+c), example: 2018776
<br>
paste the ID in <a href='http://polygons.openstreetmap.fr/index.py'>http://polygons.openstreetmap.fr/index.py</a> and download the polygon in geojson format
		  </p>
		   <form method="post" action="options.php" enctype='multipart/form-data'>
            <?php
               settings_fields("Geolocation_Block_Page");
  
               do_settings_sections("Geolocation_Block_Page");
                 
               submit_button(); 
            ?>
         </form>
		<!--<form action="" method="post">
			<div>Block city 3 json<textarea cols="100" class="geocomplete" value="<?php echo @$geolocationData['city1']; ?>" name="city1" type="text"><?php echo file_get_contents(__DIR__ . '/geojsons/city1.json'); ?></textarea><input type="hidden" name="city1code" value="<?php echo @$geolocationData['city1code']; ?>"></div>
			<div>Block city 3 json<textarea  cols="100" class="geocomplete" name="city2" type="text" value="<?php echo @$geolocationData['city2']; ?>"><?php echo file_get_contents(__DIR__ . '/geojsons/city2.json'); ?></textarea></textarea><input type="hidden" name="city2code" value="<?php echo @$geolocationData['city2code']; ?>"></div>
			<div>Block city 3 json<textarea cols="100" class="geocomplete" name="city3" type="text" value="<?php echo @$geolocationData['city3']; ?>"><?php echo file_get_contents(__DIR__ . '/geojsons/city3.json'); ?></textarea><input type="hidden" name="city3code" value="<?php echo @$geolocationData['city3code']; ?>"></div>
			<input type="submit" class="button" />
		</form>-->
		
		 <script>
      $(function(){
           /*
        $(".geocomplete").geocomplete().bind("geocode:result", function(event, result){ 
         
			var inputEl = $(this);
			var cityCode;
			
			for (var i = 0; i < result.address_components.length; i++) {
				var addressComponents = result.address_components[i];
				
				for (var j = 0; j < addressComponents.types.length; j++) {
					if (addressComponents.types[j] == 'administrative_area_level_1') {
						cityCode = addressComponents.long_name;
						break;
					}
				}					
			}
			
			inputEl.attr("value", result.formatted_address);
			inputEl.parent().find('[type=hidden]').val(cityCode);
            console.log(result);
          }); 
		  */
      });
    </script>
		<?php
		$html = ob_get_contents();
		ob_end_clean();
		echo $html;
	}
}

new Geolocation_Block_Page;


add_action( 'init', 'Geolocation_Block_process_post' );

function Geolocation_Block_process_post() {
	if(current_user_can('administrator') ) {
		//return true;
	}
	
	
$ip = $_SERVER['REMOTE_ADDR'];
$url = "http://ip-api.com/json/" . $ip;
$response = wp_remote_get( $url );
$geocode = array();

if ( is_array( $response ) ) {
  $body = json_decode($response['body'], true);
  $geocode['lat'] = $body['lat'];
  $geocode['lng'] = $body['lon'];
  
  // HACK 15.590747, 105.839818
  //$geocode['lat'] = "15.590747";
  //$geocode['lng'] = "105.839818";
  // END HACK
} 

if (!empty($geocode)) {
	$url = "https://maps.googleapis.com/maps/api/geocode/json?language=en&latlng=" . $geocode['lat'] . "," . $geocode['lng'] . "&key=" . GEOLOCATION_BLOCK_API_KEY;
	$response = wp_remote_get( $url );
	$city = null;
	
	if ( is_array( $response ) ) {
	  $body = json_decode($response['body'], true); 
	  $address = $body['results'][0]; 
	  foreach ($address['address_components'] as $component) {
		  if (in_array('administrative_area_level_1', $component['types'])) {
			$city = trim($component['long_name']);
		  }
	  }
	   
	  
	  $geolocationData = json_decode(get_option('geolocation_block_city_data'), true);
	  
	  foreach ($geolocationData as $loc) {
		if ($city == $loc) {
			geolocation_block_redirect_domain(); 
		}  
	  }
	  
	  $file_paths = array(
	  get_option('city1-file'),
	  get_option('city2-file'),
	  get_option('city3-file'),
	  );
	 
	 
	 foreach ($file_paths as $file_path) {
		 $geodata = json_decode(file_get_contents($file_path), true);
		 $geodata = $geodata['geometries'][0]['coordinates'][0][0]; 
			$geofence = new Polygon();

			foreach ($geodata as $data) { 
				$geofence->addPoint(new Coordinate($data[1],$data[0]));
			} 
 
		$insidePoint = new Coordinate($geocode['lat'], $geocode['lng']);
 
		if ($geofence->contains($insidePoint)) {
			geolocation_block_redirect_domain();
		}
	 }
	  
	} 
}

}

function geolocation_block_redirect_domain()
{
	wp_redirect(get_option('redirect-domain'));
	exit;
}

function geolocation_block_settings_page()
{
    add_settings_section("Geolocation_Block_Page", "Geolocation Block", null, "Geolocation_Block_Page");
    add_settings_field("city1-file", "City 1 GeoJson file", "city1_file_display", "Geolocation_Block_Page", "Geolocation_Block_Page");  
    add_settings_field("city2-file", "City 2 GeoJson file", "city2_file_display", "Geolocation_Block_Page", "Geolocation_Block_Page");  
    add_settings_field("city3-file", "City 3 GeoJson file", "city3_file_display", "Geolocation_Block_Page", "Geolocation_Block_Page");  
    add_settings_field("redirect-domain", "Redirect Domain", "redirect_domain_display", "Geolocation_Block_Page", "Geolocation_Block_Page");  
    register_setting("Geolocation_Block_Page", "city1-file", "geolocation_block_handle_file_upload1");
    register_setting("Geolocation_Block_Page", "city2-file", "geolocation_block_handle_file_upload2");
    register_setting("Geolocation_Block_Page", "city3-file", "geolocation_block_handle_file_upload3");
    register_setting("Geolocation_Block_Page", "redirect-domain");
}

function geolocation_block_handle_file_upload1($option)
{

  if(!empty($_FILES["city1-file"]["tmp_name"]))
  {
    $urls = wp_handle_upload($_FILES["city1-file"], array('test_form' => FALSE));
    $temp = $urls["url"];
 
    return $temp;   
  }
  
   return get_option('city1-file');
}

function geolocation_block_handle_file_upload2($option)
{

  if(!empty($_FILES["city2-file"]["tmp_name"]))
  {
    $urls = wp_handle_upload($_FILES["city2-file"], array('test_form' => FALSE));
    $temp = $urls["url"];
 
    return $temp;   
  }
  
 return get_option('city2-file');
}

function geolocation_block_handle_file_upload3($option)
{

  if(!empty($_FILES["city3-file"]["tmp_name"]))
  {
    $urls = wp_handle_upload($_FILES["city3-file"], array('test_form' => FALSE));
    $temp = $urls["url"];
 
    return $temp;   
  }
  
  return get_option('city3-file');
}

function city1_file_display()
{
   ?>
        <input type="file" name="city1-file" /> 
        <?php echo get_option('city1-file'); ?>
   <?php
}


function city2_file_display()
{
   ?>
        <input type="file" name="city2-file" /> 
        <?php echo get_option('city2-file'); ?>
   <?php
}


function city3_file_display()
{
   ?>
        <input type="file" name="city3-file" /> 
        <?php echo get_option('city3-file'); ?>
   <?php
}

function redirect_domain_display()
{
   ?>
        <input style="width:100%" width="100%" type="text" name="redirect-domain" value="<?php echo get_option('redirect-domain'); ?>"   /> 
       
   <?php
}

add_action("admin_init", "geolocation_block_settings_page");
