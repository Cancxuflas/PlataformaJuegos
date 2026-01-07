<?php

namespace App\Controller;

use App\Entity\User;
use App\Entity\Juego;
use App\Entity\Aplicacion;
use App\Repository\UserRepository;
use App\Repository\JuegoRepository;
use App\Repository\AplicacionRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class AdminController extends AbstractController
{
    #[Route('/admin', name: 'app_admin', methods: ['GET', 'POST'])]
    public function index(
        Request $request,
        UserRepository $userRepository,
        JuegoRepository $juegoRepository,
        AplicacionRepository $aplicacionRepository,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $passwordHasher,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        $error = null;
        $success = null;

        if ($request->isMethod('POST')) {
            $action = $request->request->get('action');
            $token = new CsrfToken('admin_panel', $request->request->get('_token'));
            if (!$csrfTokenManager->isTokenValid($token)) {
                throw new AccessDeniedException('CSRF token inválido');
            }

            // ===== USUARIOS =====
            if ($action === 'create_user') {
                $email = trim((string) $request->request->get('email'));
                $nombre = trim((string) $request->request->get('nombre'));
                $password = (string) $request->request->get('password');
                $isAdmin = $request->request->get('is_admin') === '1';

                if (!$email || !$nombre || !$password) {
                    $error = 'Todos los campos son obligatorios.';
                } elseif ($userRepository->findOneBy(['email' => $email])) {
                    $error = 'Ya existe un usuario con ese email.';
                } else {
                    $user = new User();
                    $user->setEmail($email);
                    $user->setNombre($nombre);
                    $user->setRoles($isAdmin ? ['ROLE_ADMIN'] : ['ROLE_USER']);
                    $hashed = $passwordHasher->hashPassword($user, $password);
                    $user->setToken($hashed);
                    $user->setEstado(true);
                    $user->setFechaRegistro(new \DateTimeImmutable());
                    $user->setRol($isAdmin ? 'ADMIN' : 'USER');

                    $em->persist($user);
                    $em->flush();
                    $success = 'Usuario creado correctamente.';
                }
            }

            if ($action === 'delete_user') {
                $userId = (int) $request->request->get('user_id');
                if ($userId === $this->getUser()?->getId()) {
                    $error = 'No puedes eliminar tu propio usuario mientras estás conectado.';
                } else {
                    $user = $userRepository->find($userId);
                    if ($user) {
                        $em->remove($user);
                        $em->flush();
                        $success = 'Usuario eliminado.';
                    }
                }
            }

            // ===== JUEGOS =====
            if ($action === 'create_game') {
                $nombre = trim((string) $request->request->get('game_nombre'));
                $descripcion = trim((string) $request->request->get('game_description'));
                $aplicacionId = (int) $request->request->get('aplicacion_id');

                if (!$nombre) {
                    $error = 'El nombre del juego es obligatorio.';
                } else {
                    // Generar token único
                    $tokenJuego = bin2hex(random_bytes(16));

                    // Buscar o usar primera aplicación
                    $aplicacion = $aplicacionRepository->find($aplicacionId);
                    if (!$aplicacion) {
                        $aplicacion = $aplicacionRepository->findOneBy(['estado' => true]);
                    }

                    if (!$aplicacion) {
                        $error = 'No hay aplicaciones disponibles.';
                    } else {
                        $juego = new Juego();
                        $juego->setNombre($nombre);
                        $juego->setDescription($descripcion ?: null);
                        $juego->setTokenJuego($tokenJuego);
                        $juego->setEstado(true);
                        $juego->setAplicacion($aplicacion);

                        $em->persist($juego);
                        $em->flush();
                        $success = 'Juego creado correctamente.';
                    }
                }
            }

            if ($action === 'delete_game') {
                $gameId = (int) $request->request->get('game_id');
                $juego = $juegoRepository->find($gameId);
                if ($juego) {
                    $em->remove($juego);
                    $em->flush();
                    $success = 'Juego eliminado.';
                } else {
                    $error = 'Juego no encontrado.';
                }
            }

            if ($action === 'toggle_game') {
                $gameId = (int) $request->request->get('game_id');
                $juego = $juegoRepository->find($gameId);
                if ($juego) {
                    $juego->setEstado(!$juego->isEstado());
                    $em->flush();
                    $success = 'Estado del juego actualizado.';
                } else {
                    $error = 'Juego no encontrado.';
                }
            }
        }

        $users = $userRepository->findAll();
        $juegos = $juegoRepository->findAll();
        $aplicaciones = $aplicacionRepository->findAll();

        return $this->render('admin/index.html.twig', [
            'users' => $users,
            'juegos' => $juegos,
            'aplicaciones' => $aplicaciones,
            'error' => $error,
            'success' => $success,
        ]);
    }
}