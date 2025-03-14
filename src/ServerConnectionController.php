<?php

/*
 * Copyright (C) 2025 w-tomasz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Description of ServerConnectionController
 *
 * @author w-tomasz
 */
namespace GlpiPlugin\Wazuh\Controller;

use GlpiPlugin\Wazuh\Model\ServerConnection;
use Html;
use Session;
use Plugin;

class ServerConnectionController extends \CommonGLPI {
    
    /**
     * Metoda obsługująca dodawanie nowego połączenia serwerowego
     * 
     * @return void
     */
    public function addServerConnection() {
        // Sprawdzenie uprawnień
        Session::checkRight("plugin_wazuh_connection", CREATE);
        
        // Sprawdzenie tokenu CSRF
        if (!isset($_POST['_glpi_csrf_token']) || !Session::validateCSRFToken($_POST['_glpi_csrf_token'])) {
            Html::displayErrorAndDie(__("Błąd sesji. Proszę odświeżyć stronę i spróbować ponownie.", "Wazuh"));
        }
        
        // Sprawdzenie wymaganych pól
        $requiredFields = ['server_name', 'ip_address', 'port', 'protocol'];
        $missingFields = [];
        
        foreach ($requiredFields as $field) {
            if (empty($_POST[$field])) {
                $missingFields[] = $field;
            }
        }
        
        if (!empty($missingFields)) {
            Session::addMessageAfterRedirect(
                __('Proszę wypełnić wszystkie wymagane pola: ', \src\PluginConfig::APP_NAME) . implode(', ', $missingFields),
                false,
                ERROR
            );
            Html::back();
            return;
        }
        
        // Walidacja adresu IP
        if (!filter_var($_POST['ip_address'], FILTER_VALIDATE_IP)) {
            Session::addMessageAfterRedirect(
                __('Podany adres IP jest nieprawidłowy.', 'Wazuh'),
                false,
                ERROR
            );
            Html::back();
            return;
        }
        
        // Walidacja portu
        if (!is_numeric($_POST['port']) || $_POST['port'] < 1 || $_POST['port'] > 65535) {
            Session::addMessageAfterRedirect(
                __('Podany port jest nieprawidłowy. Zakres portów: 1-65535.', \src\PluginConfig::APP_NAME),
                false,
                ERROR
            );
            Html::back();
            return;
        }
        
        // Tworzenie nowego obiektu połączenia
        $connection = new ServerConnection();
        
        // Przygotowanie danych do zapisania
        $input = [
            'server_name' => $_POST['server_name'],
            'ip_address' => $_POST['ip_address'],
            'port' => (int)$_POST['port'],
            'protocol' => ($_POST['protocol'] === 'other' && !empty($_POST['other_protocol'])) 
                ? $_POST['other_protocol'] 
                : $_POST['protocol'],
            'username' => isset($_POST['username']) ? $_POST['username'] : '',
            'password' => isset($_POST['password']) ? $_POST['password'] : '',
            'description' => isset($_POST['description']) ? $_POST['description'] : '',
            'status' => isset($_POST['active']) ? 1 : 0,
            'date_created' => date('Y-m-d H:i:s'),
            'date_modified' => date('Y-m-d H:i:s'),
            'entities_id' => $_SESSION['glpiactive_entity']
        ];
        
        // Zapisywanie hasła w bezpieczny sposób (jeśli podano)
        if (!empty($input['password'])) {
            // W rzeczywistym przypadku należy użyć bezpiecznej metody przechowywania haseł
            // np. zaszyfrować hasło lub skorzystać z mechanizmu GLPI do przechowywania poświadczeń
            $input['password'] = $this->encryptPassword($input['password']);
        }
        
        // Dodawanie rekordu do bazy danych
        $newID = $connection->add($input);
        
        if ($newID) {
            // Sukces
            Session::addMessageAfterRedirect(
                __('Połączenie do serwera zostało pomyślnie dodane.', \src\PluginConfig::APP_NAME),
                true,
                INFO
            );
            
            // Opcjonalnie - test połączenia po dodaniu
            if (isset($_POST['test_after_add']) && $_POST['test_after_add'] == 1) {
                $this->testServerConnection($newID);
            }
            
            // Przekierowanie do strony z listą połączeń
            Html::redirect(Plugin::getWebDir(\src\PluginConfig::APP_NAME) . '/front/serverconnection.php');
        } else {
            // Błąd
            Session::addMessageAfterRedirect(
                __('Wystąpił błąd podczas dodawania połączenia. Spróbuj ponownie.', \src\PluginConfig::APP_NAME),
                false,
                ERROR
            );
            Html::back();
        }
    }
    
    /**
     * Metoda do testowania połączenia
     * 
     * @param int $id ID połączenia do przetestowania
     * @return bool Wynik testu (true/false)
     */
    public function testServerConnection($id) {
        $connection = new ServerConnection();
        if (!$connection->getFromDB($id)) {
            Session::addMessageAfterRedirect(
                __('Nie znaleziono połączenia o podanym ID.', \src\PluginConfig::APP_NAME),
                false,
                ERROR
            );
            return false;
        }
        
        // Implementacja testu połączenia zależna od protokołu
        $testResult = false;
        $errorMessage = '';
        
        switch ($connection->fields['protocol']) {
            case 'http':
            case 'https':
                $testResult = $this->testHttpConnection($connection);
                break;
            case 'ssh':
                $testResult = $this->testSshConnection($connection);
                break;
            case 'ftp':
            case 'sftp':
                $testResult = $this->testFtpConnection($connection);
                break;
            default:
                $errorMessage = __('Testowanie tego protokołu nie jest obecnie obsługiwane.', \src\PluginConfig::APP_NAME);
                break;
        }
        
        // Aktualizacja statusu ostatniego testu
        $connection->update([
            'id' => $id,
            'last_test_date' => date('Y-m-d H:i:s'),
            'last_test_status' => $testResult ? 1 : 0,
            'last_test_message' => $errorMessage
        ]);
        
        // Wyświetlenie odpowiedniego komunikatu
        if ($testResult) {
            Session::addMessageAfterRedirect(
                __('Test połączenia zakończony powodzeniem.', \src\PluginConfig::APP_NAME),
                true,
                INFO
            );
        } else {
            Session::addMessageAfterRedirect(
                __('Test połączenia nie powiódł się: ', \src\PluginConfig::APP_NAME) . $errorMessage,
                false,
                ERROR
            );
        }
        
        return $testResult;
    }
    
    /**
     * Metoda do testowania połączenia HTTP/HTTPS
     * 
     * @param ServerConnection $connection Obiekt połączenia
     * @return bool Wynik testu
     */
    private function testHttpConnection($connection) {
        $url = $connection->fields['protocol'] . '://' . $connection->fields['ip_address'] . ':' . $connection->fields['port'];
        
        // Utworzenie kontekstu z timeoutem
        $context = stream_context_create([
            'http' => [
                'timeout' => 5 // timeout w sekundach
            ]
        ]);
        
        // Próba połączenia
        $result = @file_get_contents($url, false, $context);
        
        return ($result !== false);
    }
    
    /**
     * Metoda do testowania połączenia SSH
     * 
     * @param ServerConnection $connection Obiekt połączenia
     * @return bool Wynik testu
     */
    private function testSshConnection($connection) {
        // Wymagana instalacja rozszerzenia SSH2 dla PHP
        if (!function_exists('ssh2_connect')) {
            return false;
        }
        
        $connection_id = @ssh2_connect(
            $connection->fields['ip_address'],
            $connection->fields['port'],
            [],
            [
                'disconnect' => function($reason, $message, $language) {
                    // obsługa rozłączenia
                }
            ]
        );
        
        if (!$connection_id) {
            return false;
        }
        
        // Jeśli podano dane logowania, próbujemy się zalogować
        if (!empty($connection->fields['username']) && !empty($connection->fields['password'])) {
            $password = $this->decryptPassword($connection->fields['password']);
            $auth = @ssh2_auth_password($connection_id, $connection->fields['username'], $password);
            return $auth;
        }
        
        // Sam fakt nawiązania połączenia uznajemy za sukces
        return true;
    }
    
    /**
     * Metoda do testowania połączenia FTP/SFTP
     * 
     * @param ServerConnection $connection Obiekt połączenia
     * @return bool Wynik testu
     */
    private function testFtpConnection($connection) {
        if ($connection->fields['protocol'] === 'ftp') {
            // Połączenie FTP
            $conn = @ftp_connect($connection->fields['ip_address'], $connection->fields['port'], 5);
            
            if (!$conn) {
                return false;
            }
            
            // Próba logowania jeśli podano dane
            if (!empty($connection->fields['username']) && !empty($connection->fields['password'])) {
                $password = $this->decryptPassword($connection->fields['password']);
                $login = @ftp_login($conn, $connection->fields['username'], $password);
                @ftp_close($conn);
                return $login;
            }
            
            @ftp_close($conn);
            return true;
        } else {
            // Połączenie SFTP (wymaga rozszerzenia SSH2)
            return $this->testSshConnection($connection);
        }
    }
    
    /**
     * Metoda do szyfrowania hasła
     * 
     * @param string $password Hasło do zaszyfrowania
     * @return string Zaszyfrowane hasło
     */
    private function encryptPassword($password) {
        // W rzeczywistym projekcie powinieneś użyć bezpiecznej metody szyfrowania
        // lub skorzystać z mechanizmów GLPI do przechowywania poświadczeń
        return base64_encode($password);
    }
    
    /**
     * Metoda do odszyfrowania hasła
     * 
     * @param string $encryptedPassword Zaszyfrowane hasło
     * @return string Odszyfrowane hasło
     */
    private function decryptPassword($encryptedPassword) {
        // Odpowiednia metoda deszyfrowania
        return base64_decode($encryptedPassword);
    }
}