<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Domain\Service\AuthService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Slim\Views\Twig;

class AuthController extends BaseController
{
    public function __construct(
        Twig $view,
        private AuthService $authService,
        private LoggerInterface $logger,
    ) {
        parent::__construct($view);
    }

    public function showRegister(Request $request, Response $response): Response
    {
        // TODO: you also have a logger service that you can inject and use anywhere; file is var/app.log
        $this->logger->info('Register page requested');

        return $this->render($response, 'auth/register.twig');
    }

    public function register(Request $request, Response $response): Response
    {
        
        // TODO: call corresponding service to perform user registration
    $data = (array)$request->getParsedBody();
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    try {
        $this->authService->register($username, $password);

        $this->logger->info("User registered: {$username}");

        return $response->withHeader('Location', '/login')->withStatus(302);
    } catch (\Exception $e) {
        $this->logger->error("Registration failed for {$username}: " . $e->getMessage());
        return $this->render($response, 'auth/register.twig', [
            'error' => $e->getMessage(),
            'username' => $username
        ]);
    }
        //return $response->withHeader('Location', '/login')->withStatus(302);
    }

    public function showLogin(Request $request, Response $response): Response
    {
        return $this->render($response, 'auth/login.twig');
    }

    public function login(Request $request, Response $response): Response
    {
        // TODO: call corresponding service to perform user login, handle login failures
    $data = (array)$request->getParsedBody();
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    
    try {
        $user = $this->authService->login($username, $password);

        if ($user) {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['user_id'] = $user['id'];

            $this->logger->info("User logged in: {$username}");

            return $response->withHeader('Location', '/dashboard')->withStatus(302);
        } else {
            $error = 'Invalid username or password.';
            $this->logger->warning("Failed login attempt for username: {$username}");
            return $this->render($response, 'auth/login.twig', [
                'error' => $error,
                'username' => $username
            ]);
        }
    } catch (\Exception $e) {
        // Handle other errors
        $this->logger->error("Login error for {$username}: " . $e->getMessage());
        return $this->render($response, 'auth/login.twig', [
            'error' => 'An error occurred during login.',
            'username' => $username
        ]);
    }


        //return $response->withHeader('Location', '/')->withStatus(302);
    }

    public function logout(Request $request, Response $response): Response
    {
        // TODO: handle logout by clearing session data and destroying session
        if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $_SESSION = [];

    // Destroy the session
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();

    $this->logger->info("User logged out.");

    // Redirect to login page
    return $response->withHeader('Location', '/login')->withStatus(302);
        //return $response->withHeader('Location', '/login')->withStatus(302);
    }
}
