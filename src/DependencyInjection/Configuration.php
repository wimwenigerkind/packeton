<?php

namespace Packeton\DependencyInjection;

use Firebase\JWT\JWT;
use Packeton\Composer\MetadataFormat;
use Packeton\Integrations\Factory\OAuth2FactoryInterface;
use Packeton\Integrations\Model\AppUtils;
use Packeton\Service\DistConfig;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    public function __construct(protected $factories)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('packeton');
        $rootNode = $treeBuilder->getRootNode();

        $archiveNormalizer = static function(mixed $value): bool|array {
            $allFlags = [DistConfig::FLAG_REPLACE, DistConfig::FLAG_MIRROR];
            if ($value === true) {
                return $allFlags;
            }
            $value = is_string($value) ? [$value] : $value;
            if (is_array($value) && $diff = array_diff($value, $allFlags)) {
                throw new \InvalidArgumentException(sprintf('packeton->archive support only [mirror, replace] options, but given %s', json_encode($diff)));
            }
            return is_array($value) ? $value : [];
        };

        $rootNode
            ->children()
                ->booleanNode('github_no_api')->end()
                ->scalarNode('rss_max_items')->defaultValue(40)->end()
                ->arrayNode('metadata')
                    ->children()
                        ->enumNode('format')->values(array_map(fn($o) => $o->value, MetadataFormat::cases()))->end()
                        ->scalarNode('info_cmd_message')->end()
                    ->end()
                ->end()
                ->booleanNode('anonymous_access')->defaultFalse()->end()
                ->booleanNode('anonymous_archive_access')->defaultFalse()->end()
                ->arrayNode('web_protection')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('repo_hosts')
                            ->example(['repo.packagist.com', '*', '!app.packagist.com'])
                            ->scalarPrototype()->end()
                        ->end()
                        ->scalarNode('allow_ips')->end()
                        ->scalarNode('custom_page')->end()
                        ->integerNode('status_code')->end()
                        ->scalarNode('content_type')->end()
                    ->end()
                ->end()
                ->booleanNode('health_check')->defaultTrue()->end()
                ->integerNode('max_import')->end()
                ->variableNode('archive')
                    ->beforeNormalization()->always()->then($archiveNormalizer)->end()
                    ->defaultFalse()
                ->end()
                ->arrayNode('artifacts')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('allowed_paths')
                            ->defaultValue(['%composer_home_dir%/artifacts'])
                            ->scalarPrototype()->end()
                        ->end()
                        ->arrayNode('support_types')
                            ->example(['gz', 'tar', 'tgz', 'zip'])
                            ->defaultValue(['zip'])
                            ->scalarPrototype()->end()
                        ->end()
                        ->scalarNode('artifact_storage')
                            ->defaultValue('%composer_home_dir%/artifact_storage')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('jwt_authentication')
                    ->children()
                        ->enumNode('algo')
                            ->info("Sign algo, default EdDSA libsodium")
                            ->defaultNull()
                            ->values(\array_keys(JWT::$supported_algs))
                        ->end()
                        ->scalarNode('private_key')->cannotBeEmpty()->end()
                        ->scalarNode('public_key')->cannotBeEmpty()->end()
                        ->booleanNode('passphrase')->defaultNull()->end()
                    ->end()
                ->end()
                ->arrayNode('archive_options')
                    ->children()
                        ->scalarNode('format')->defaultValue('zip')->end()
                        ->scalarNode('basedir')->cannotBeEmpty()->end()
                        ->scalarNode('endpoint')->defaultNull()->end()
                        ->booleanNode('prebuild_zipball')->end()
                        ->booleanNode('include_archive_checksum')->defaultFalse()->end()
                    ->end()
                ->end()
            ->end();

        $rootNode
            ->validate()
            ->always(function ($values) {
                if (($values['archive'] ?? false) && !isset($values['archive_options'])) {
                    throw new \InvalidArgumentException('archive_options is required if packeton->archive is not false');
                }

                return $values;
            })->end();

        $this->addMirrorsRepositoriesConfiguration($rootNode);
        $this->addIntegrationSection($rootNode, $this->factories);

        return $treeBuilder;
    }

    private function addMirrorsRepositoriesConfiguration(ArrayNodeDefinition|NodeDefinition $node)
    {
        /** @var ArrayNodeDefinition $mirrorNodeBuilder */
        $mirrorNodeBuilder = $node
            ->children()
                ->arrayNode('mirrors')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype();

        $jsonNormalizer = static function ($json) {
            if (\is_string($json) && \is_array($opt = @json_decode($json, true))) {
                return $opt;
            }
            if (!\is_array($json)) {
                throw new \InvalidArgumentException('This node must be array or JSON string');
            }

            return $json;
        };

        $mirrorNodeBuilder
            ->children()
                ->scalarNode('url')->end()
                ->variableNode('options')
                    ->beforeNormalization()->always()->then($jsonNormalizer)->end()
                ->end()
                ->variableNode('composer_auth')
                    ->beforeNormalization()->always()->then($jsonNormalizer)->end()
                ->end()
                ->arrayNode('http_basic')
                    ->children()
                        ->scalarNode('username')->isRequired()->end()
                        ->scalarNode('password')->isRequired()->end()
                    ->end()
                ->end()
                ->scalarNode('sync_interval')->end()
                ->booleanNode('sync_lazy')->end()
                ->booleanNode('enable_dist_mirror')->defaultTrue()->end()
                ->booleanNode('parent_notify')->end()
                ->booleanNode('disable_v1')->end()
                ->booleanNode('public_access')->end()
                ->variableNode('git_ssh_keys')->end()
                ->scalarNode('info_cmd_message')->end()
                ->scalarNode('without_path_prefix')->end()
                ->scalarNode('logo')->end()
                ->integerNode('available_packages_count_limit')->end()
                ->arrayNode('available_package_patterns')
                    ->scalarPrototype()->end()
                ->end()
                ->arrayNode('available_packages')
                    ->scalarPrototype()->end()
                ->end()
                ->arrayNode('chain_providers')
                    ->scalarPrototype()->end()
                ->end()
            ->end()
        ;

        $defaultLogos = [
            'asset-packagist.org' => '/packeton/img/logo/asset-packagist.svg',
            'packages.drupal.org' => '/packeton/img/logo/drupl.png',
            'repo.packagist.org' => '/packeton/img/logo/packagist.png',
            'packagist.org' => '/packeton/img/logo/packagist.png',
            'wpackagist.org' => '/packeton/img/logo/wordpress.png',
            'repo.magento.com' => '/packeton/img/logo/magento.png',
            'satis.oroinc.com' => '/packeton/img/logo/orocrm.png',
            'packagist.oroinc.com' => '/packeton/img/logo/orocrm.png',
            'packages.firegento.com' => '/packeton/img/logo/magento.png',
            'packagist.com' => '/packeton/img/logo/logo-packagist.svg',
            'repo.packagist.com' => '/packeton/img/logo/logo-packagist.svg',
            'nova.laravel.com' => '/packeton/img/logo/nova-laravel.png',
        ];

        $mirrorNodeBuilder
            ->beforeNormalization()
                ->always()
                ->then(static function ($provider) use ($defaultLogos) {
                    if (!isset($provider['url'])) {
                        return $provider;
                    }
                    $host = \parse_url($provider['url'], \PHP_URL_HOST);

                    $provider['url'] = \rtrim($provider['url'], '/');
                    // packagist.org is mark lazy by default.
                    $isOfficial = \in_array($host, ['packagist.org','repo.packagist.org']);
                    if ($isOfficial && !isset($provider['sync_lazy'])) {
                        // packagist.org is very big and have v2, sync on fly by default.
                        $provider['sync_lazy'] = true;
                    }
                    if (!$isOfficial && !isset($provider['parent_notify'])) {
                        // Disable download stats for non packagist.org, by default
                        $provider['parent_notify'] = false;
                    }
                    if (!\array_key_exists('logo', $provider) && isset($defaultLogos[$host])) {
                        $provider['logo'] = $defaultLogos[$host];
                    }

                    return $provider;
                })
            ->end();
    }

    /**
     * @param ArrayNodeDefinition $rootNode
     * @param array|\Packeton\Integrations\Factory\OAuth2FactoryInterface[] $factories
     */
    private function addIntegrationSection(ArrayNodeDefinition $rootNode, array $factories)
    {
        $nodeBuilder = $rootNode
            ->children()
                ->arrayNode('integrations')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype();

        $nodeBuilder->children()
            ->booleanNode('enabled')->defaultTrue()->end()
            ->scalarNode('base_url')->end()
            ->enumNode('clone_preference')->values(AppUtils::$clonePref)->end()
            ->booleanNode('repos_synchronization')->end()
            ->booleanNode('pull_request_review')->end()
            ->booleanNode('disable_hook_repos')->end()
            ->booleanNode('disable_hook_org')->end()
            ->scalarNode('webhook_url')->info('Static current host')->end()
            ->scalarNode('svg_logo')->end()
            ->scalarNode('logo')->end()
            ->scalarNode('login_title')->end()
            ->scalarNode('login_control_expression')
                ->beforeNormalization()
                ->always(function ($value) {
                    return is_string($value) && str_contains($value, '{%') ? 'base64:' . base64_encode($value) : $value;
                })
                ->end()
            ->end()
            ->booleanNode('login_control_expression_debug')->end()
            ->booleanNode('allow_login')
                ->defaultFalse()
            ->end()
            ->booleanNode('allow_register')
                ->defaultFalse()
            ->end()
            ->arrayNode('default_roles')
                ->scalarPrototype()->end()
            ->end()
            ->scalarNode('icon')->end()
            ->scalarNode('description')->end();

        foreach ($factories as $factory) {
            $name = \str_replace('-', '_', $factory->getKey());
            $factoryNode = $nodeBuilder->children()
                ->arrayNode($name)
                ->canBeUnset();

            $factory->addConfiguration($factoryNode);
        }

        $icons = $this->defaultIconsData();
        $nodeBuilder->beforeNormalization()
            ->always()
            ->then(static function ($provider) use ($icons) {
                $keys = array_intersect(array_keys($provider), array_keys($icons));
                $name = reset($keys);
                if (!$name || !isset($icons[$name])) {
                    return $provider;
                }

                $provider += $icons[$name];
                return $provider;
            })
            ->end();

        //
        $nodeBuilder->end();
    }

    private function defaultIconsData(): array
    {
        return [
            'github' => [
                'logo' => '/packeton/img/logo/github.png',
                'svg_logo' => 'svg/github.html.twig',
                'login_title' => 'Login with GitHub',
            ],
            'githubapp' => [
                'logo' => '/packeton/img/logo/github.png',
                'svg_logo' => 'svg/github.html.twig',
                'login_title' => 'Login with GitHub',
            ],
            'gitlab' => [
                'logo' => '/packeton/img/logo/gitlab.png',
                'svg_logo' => 'svg/gitlab.html.twig',
                'login_title' => 'Login with GitLab',
            ],
            'gitea' => [
                'logo' => '/packeton/img/logo/gitea.png',
                'svg_logo' => 'svg/gitea.html.twig',
                'login_title' => 'Login with Gitea',
            ],
            'bitbucket' => [
                'logo' => '/packeton/img/logo/bitbucket.png',
                'svg_logo' => 'svg/bitbucket.html.twig',
                'login_title' => 'Login with Bitbucket',
            ],
            'google' => [
                'svg_logo' => 'svg/google.html.twig',
                'login_title' => 'Login with Google',
            ],
            'entra_id' => [
                'svg_logo' => 'svg/entra_id.html.twig',
                'login_title' => 'Login with Entra ID',
            ]
        ];
    }
}
