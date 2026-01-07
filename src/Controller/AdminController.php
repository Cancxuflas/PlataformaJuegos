<?php

namespace App\Controller;

use App\Entity\User;
use App\Entity\Juego;
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
        $tab = $request->query->get('tab', 'users');

        if ($request->isMethod('POST')) {
            $action = $request->request->get('action');
            $type = $request->request->get('type', 'user');
            $tokenId = $type === 'juego' ? 'admin_games' : 'admin_users';
            $token = new CsrfToken($tokenId, $request->request->get('_token'));
            
            if (!$csrfTokenManager->isTokenValid($token)) {
                throw new AccessDeniedException('CSRF token inválido');
            }

            // USUARIOS
            if ($type === 'user' && $action === 'create') {
                $email = trim((string) $request->request->get('email'));
                $nombre = trim((string) $request->request->get('nombre'));
                $password = (string) $request->request->get('password');
                $isAdmin = $request->request->get('is_admin') === '1';

                if (!$email || !$nombre || !$password) {
                    $error = 'Todos los campos del usuario son obligatorios.';
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

            if ($type === 'user' && $action === 'delete') {
                $userId = (int) $request->request->get('user_id');
                if ($userId === $this->getUser()?->getId()) {
                    $error = 'No puedes eliminar tu propio usuario mientras estás conectado.';
                } else {
                    $user = $userRepository->find($userId);
                    if ($user) {
                        $em->remove($user);
                        $em->flush();
                        $success = 'Usuario eliminado correctamente.';
                    }
                }
            }

            // JUEGOS
            if ($type === 'juego' && $action === 'create') {
                $nombre = trim((string) $request->request->get('nombre_juego'));
                $token_juego = trim((string) $request->request->get('token_juego'));
                $descripcion = trim((string) $request->request->get('descripcion'));
                $aplicacionId = (int) $request->request->get('aplicacion_id');

                if (!$nombre || !$token_juego || !$aplicacionId) {
                    $error = 'Todos los campos del juego son obligatorios.';
                } elseif ($juegoRepository->findOneBy(['tokenJuego' => $token_juego])) {
                    $error = 'Ya existe un juego con ese token.';
                } else {
                    $aplicacion = $aplicacionRepository->find($aplicacionId);
                    if (!$aplicacion) {
                        $error = 'Aplicación no encontrada.';
                    } else {
                        $juego = new Juego();
                        $juego->setNombre($nombre);
                        $juego->setTokenJuego($token_juego);
                        $juego->setDescription($descripcion ?: null);
                        $juego->setEstado(true);
                        $juego->setAplicacion($aplicacion);

                        $em->persist($juego);
                        $em->flush();
                        $success = 'Juego creado correctamente.';
                        $tab = 'games';
                    }
                }
            }

            if ($type === 'juego' && $action === 'delete') {
                $juegoId = (int) $request->request->get('juego_id');
                $juego = $juegoRepository->find($juegoId);
                if ($juego) {
                    $em->remove($juego);
                    $em->flush();
                    $success = 'Juego eliminado correctamente.';
                    $tab = 'games';
                } else {
                    $error = 'Juego no encontrado.';
                }
            }

            if ($type === 'juego' && $action === 'edit') {
                $juegoId = (int) $request->request->get('juego_id');
                $nombre = trim((string) $request->request->get('nombre_juego'));
                $descripcion = trim((string) $request->request->get('descripcion'));
                $estado = $request->request->get('estado') === '1';

                $juego = $juegoRepository->find($juegoId);
                if (!$juego) {
                    $error = 'Juego no encontrado.';
                } elseif (!$nombre) {
                    $error = 'El nombre del juego es obligatorio.';
                } else {
                    $juego->setNombre($nombre);
                    $juego->setDescription($descripcion ?: null);
                    $juego->setEstado($estado);

                    $em->flush();
                    $success = 'Juego actualizado correctamente.';
                    $tab = 'games';
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
            'tab' => $tab,
        ]);
    }
}
